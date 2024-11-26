const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const port = 3000;
require('dotenv').config();  
const axios = require('axios')

const uri =
  `${process.env?.CONNECTION_STRING}`;
app.use(cors());
app.use(bodyParser.json());

// MongoDB schemas
const userSchema = new mongoose.Schema({
  uid: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  quizzes: [
    {
      quizId: { type:  String, required: true },
      score: { type: Number, required: true },
      answers: [],
      attemptedAt: { type: Date, default: Date.now }
    }
  ]
});

const quizSchema = new mongoose.Schema({
  quiz: [
    {
      question: {
        type: String,
        required: true,
      },
      options: {
        type: Map,
        of: String, // Maps option keys to their values
        required: true,
      },
      answer: {
        type: String,
        required: true,
      },
    },
  ],
  isTimed: {
    type: Boolean,
    required: true,
  },
  totalQuestions: {
    type: Number,
    required: true,
  },
  questionType: {
    type: String,
    enum: ["True/False", "Multiple Choice", "Fill in the Blank", "Short Answer"], // Example of allowed types
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now, // Automatically stores the creation time
  },
});

const User = mongoose.model("User", userSchema);
const Quiz = mongoose.model("Quiz",quizSchema);
const noteSchema = new mongoose.Schema({
  title: String,
  content: String,
  transcripts: String,
  createdAt: { type: Date, default: Date.now },
  uid: String,
  structuredNotes: JSON,
  subject: String
});

const Note = mongoose.model("Note", noteSchema);

app.post("/omi-webhook", async (req, res) => {
  try {
    const data = req.body;
    const { uid = "" } = req.query;

    if (
      data &&
      data.structured &&
      data.structured.title &&
      data.structured.overview
    ) {
      const newNote = new Note({
        title: data.structured.title,
        content: data.structured.overview,
        uid,
        transcripts: data?.transcript_segments.map(note => note.text).join(" ")
      });
      const structuredAiNote = await structureNotes([newNote]);
      newNote.structuredNotes = structuredAiNote;
      console.log(structuredAiNote?.data?.subject, "LALALLAA");
      newNote.subject = structuredAiNote?.data?.subject;
      await newNote.save();

      res.status(200).send({ message: "Note created successfully!" });
    } else {
      res.status(400).send({ error: "Invalid data format!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal server error" });
  }
});
const authenticateToken = (req, res, next) => {
  // Get token from authorization header
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).send({ error: 'Authentication token is missing' });
  }

  try {
    // Verify and decode the token to get the uid
    const decoded = jwt.verify(token, 'your_jwt_secret');  // 'your_jwt_secret_key' should match the secret used during token creation
    req.uid = decoded.uid;  // Set decoded uid to request object
    next();
  } catch (error) {
    return res.status(403).send({ error: 'Invalid or expired token' });
  }
};

app.post("/submit-quiz", authenticateToken, async (req, res) => {
  try {
    const { uid } = req?.headers; // Extract user ID from the authenticated token
    const { quizId, score, answers } = req.body;
    const token = req.headers.authorization.split(' ')[1]; // Get Bearer token
    const userId = getUserIdFromToken(token); // Get user ID from the token
    if (!quizId || score === undefined || !Array.isArray(answers)) {
      return res.status(400).send({ error: "Invalid request data" });
    }

    // Find the user by UID
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    // Add the quiz attempt to the user's quizzes array
    user.quizzes.push({ quizId, score, answers });

    // Save the updated user
    await user.save();

    res.status(200).send({ message: "Quiz attempt saved successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal server error" });
  }
});
// Structure function (unchanged)
const structureNotes = async (rawNotes) => {
  try {
    // Combine all note contents into one string
    const notesContent = rawNotes[0]?.transcripts;
    console.log(notesContent, "OOAOAOA")
    // Send the notes to OpenAI for structuring
    const openAIResponse = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4', // or 'gpt-4o-mini', depending on your model choice
        messages: [
          {
            role: 'user',
            content: `Please break down the following notes into sections with titles, content, and true/false quiz questions: ${notesContent}.
            Your response must be structured in a JSON format.
            Example Response : 
            {
              "data": {
                "subject":"Physics",
                "chapter":"Motion in 2D Plane",
                "description":"Some description about the chapter"
                "sections": [
                  {
                    "title": "Two-Dimensional Motion",
                    "content": "In two-dimensional motion, we have both x and y components of motion. For instance, an object moving along a curved path in the x-y plane has its position described by two variables.",
                    "quiz": {
                      "Question": "In two-dimensional motion, we have only x component of motion.",
                      "Answer": "False"
                    }
                  },              
                  {
                    "title": "Acceleration in 2D",
                    "content": "Acceleration in 2D describes how the velocity of an object changes over time, also having components along the x and y axes.",
                    "quiz": {
                      "Question": "Acceleration in 2D only has a component along the x axis.",
                      "Answer": "False"
                    }
                  }
                ]
              }
            }
            
             `
            
          }
        ],
        temperature: 0.7
      },
      {
        headers: {
          Authorization: `Bearer ${process.env?.OPEN_AI_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    // Parse the structured notes response from OpenAI
    console.log(openAIResponse.data.choices[0].message.content,"ALALLAA")
    const structuredNotes = JSON.parse(openAIResponse.data.choices[0].message.content);

    return structuredNotes;
  } catch (error) {
    console.error("Error structuring notes with OpenAI:", error);
    throw new Error("Failed to structure notes");
  }
};

// Fetch and process notes route
app.get("/fetch-notes", authenticateToken, async (req, res) => {
  try {
    const { uid } = req; // UID from the token after decoding
    console.log("UID from token:", uid);

    if (!uid) {
      return res.status(400).send({ error: "UID is required" });
    }

    // Fetch notes associated with the user
    const notes = await Note.find({ uid });

    if (notes.length === 0) {
      return res.status(404).send({ message: "No notes found for the given UID" });
    }

    // Response to send to the frontend
    const notesResponse = [];

    // Loop through each note
    for (const note of notes) {
      if (note.structuredNotes) {
        // If structuredNotes field already has content, append it to the response
        notesResponse.push({
          id: note._id, // Add the note's ID
          structuredNotes: note.structuredNotes
        });
      } else {
        // If no structuredNotes, structure the note using OpenAI
        const structuredContent = await structureNotes([note]);

        // Append structured content to the response
        notesResponse.push(structuredContent);

        // Update the note's structuredNotes field in the database
        note.structuredNotes = structuredContent;
        await note.save(); // Save the updated note with structured content
      }
    }

    // Send the response back to the frontend
    res.status(200).send(notesResponse);
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal server error" });
  }
});



// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { uid, password } = req.body;

    if (!uid || !password) {
      return res.status(400).send({ error: "UID and password are required" });
    }

    const existingUser = await User.findOne({ uid });
    const token = jwt.sign({ uid: existingUser.uid }, "your_jwt_secret", {
      expiresIn: "1h",
    });
    if (existingUser) {
      // If user exists, log them in
      const isPasswordValid = await bcrypt.compare(
        password,
        existingUser.password
      );
      if (isPasswordValid) {
        return res
        .status(200)
          .send({ message: "User already exists, logged in", token });
      } else {
        return res
          .status(400)
          .send({ error: "Incorrect password for existing user" });
      }
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ uid, password: hashedPassword });
    await newUser.save();

    res.status(201).send({ message: "User registered successfully!", token });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal server error" });
  }
});
const getUserIdFromToken = (token) => {
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret');
    return decoded.userId;
  } catch (error) {
    throw new Error('Invalid token');
  }
};
// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { uid, password } = req.body;

    if (!uid || !password) {
      return res.status(400).send({ error: "UID and password are required" });
    }

    const user = await User.findOne({ uid });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send({ error: "Incorrect password" });
    }

    const token = jwt.sign({ uid: user.uid }, "your_jwt_secret", {
      expiresIn: "30d",
    });
    res.status(200).send({ message: "Logged in successfully", token });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal server error" });
  }
});
app.post('/create-quiz', authenticateToken, async (req, res) => {
  try {
    // Extract the data from the request body
    const { subject, questionType, isTimed, totalQuestions } = req.body;
    const token = req.headers.authorization.split(' ')[1]; // Get Bearer token
    const userId = getUserIdFromToken(token); // Get user ID from the token

    // Fetch the user's notes that match the subject
    const userNotes = await Note.find({ userId, subject });
    if (!userNotes || userNotes.length === 0) {
      return res.status(404).json({ message: 'No notes found for this subject' });
    }

    const chapters = userNotes.flatMap(note => note?.structuredNotes?.data?.chapter);

    // Generate questions using OpenAI for all chapters in one prompt
    const chapterQuestions = await generateQuizForChapters(chapters, questionType, totalQuestions);

    // Create a new quiz object for saving in the database
    const newQuiz = new Quiz({
      quiz: chapterQuestions,
      isTimed,
      totalQuestions,
      questionType,
      createdBy: userId, // Save the creator's user ID
      subject,          // Save the subject for context
    });

    // Save the quiz to the database
    await newQuiz.save();

    // Return the generated quiz
    return res.status(200).json({
      quiz: chapterQuestions,
      isTimed,
      totalQuestions,
      questionType,
    });

  } catch (error) {
    console.error('Error creating quiz:', error);
    return res.status(500).json({ message: 'Failed to create quiz' });
  }
});


const generateQuizForChapters = async (chapters, questionType, totalQuestions) => {
  const questionsPerChapter = Math.floor(totalQuestions / chapters.length);  // Divide questions evenly across chapters
  const remainingQuestions = totalQuestions % chapters.length;  // Handle remaining questions if total is not divisible by chapters

  // Construct a single prompt with all chapters and the number of questions per chapter
  const prompt = createOpenAIPrompt(chapters, questionType, questionsPerChapter, remainingQuestions);
  // Call OpenAI to generate questions for all chapters
  const response = await axios.post(
    'https://api.openai.com/v1/chat/completions',
    {
      model: 'gpt-4', // You can use any other model
      messages: [
        {
          role: 'user',
          content: prompt.toString(),
        }
      ],
      temperature : 0.7
    },
    {
      headers: {
        Authorization: `Bearer ${process.env?.OPEN_AI_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );

  // Process the generated questions from the OpenAI response
  const chapterQuiz = response.data.choices[0].message.content;
  const quiz = parseQuizResponse(chapterQuiz);

  return quiz;
};

// Function to create the OpenAI prompt for all chapters
const createOpenAIPrompt = (chapters, questionType, questionsPerChapter, remainingQuestions) => {
  const questionTypes = {
    'Single Correct': 'Please create multiple choice questions based on the content of each chapter.',
  };

  let chapterContent = '';
  chapters.forEach((chapter, index) => {
    chapterContent += `
      Chapter: ${chapter}
      ${questionTypes[questionType]}
      Generate ${questionsPerChapter} questions for this chapter.
    `;
  });

  // Add remaining questions to the last chapter
  if (remainingQuestions > 0) {
    const lastChapter = chapters[chapters.length - 1];
    chapterContent += `
      Chapter: ${lastChapter}
      Content: ${lastChapter}
      ${questionTypes[0]}
      Generate ${questionsPerChapter + remainingQuestions} questions for this chapter.
    `;
  }

  return `
    ${chapterContent}
    Make sure to return the questions in this format:
    {
      "data": [{
        "question": "",
        "options": {
          "Option 1": "",
          "Option 2": "",
          "Option 3": "",
          "Option 4": ""
        },
        "answer": ""
      }]
    }
  `;
};

// Function to parse the OpenAI response into quiz format
const parseQuizResponse = (responseText) => {
  // Assuming OpenAI's response will be in JSON format, we can try parsing it
  try {
    const responseJson = JSON.parse(responseText);
    return responseJson.data.map((item) => ({
      question: item.question,
      options: item.options,
      answer: item.answer,
    }));
  } catch (error) {
    console.error('Error parsing OpenAI response:', error);
    return [];
  }
};

// MongoDB connection
mongoose
  .connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB successfully!");
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection error: ", error);
  });
