import { Request, Response } from "express";
import { User } from "../models/User";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import * as yup from "yup";
import { supabase } from "../config/supabase";

dotenv.config();

const SECRET_KEY = process.env.JWT_SECRET || "secret_key";

//📌 1️⃣ NEW USER  SIGNUP

export const signup = async (req: Request, res: Response): Promise<void> => {
  const schema = yup.object().shape({
    name: yup.string().required("Name is required"),
    email: yup
      .string()
      .email("Invalid email format")
      .required("Email is required"),
    password: yup
      .string()
      .min(6, "Password must be at least 6 characters")
      .required("Password is required"),
    termsAccepted: yup.boolean().oneOf([true], "You must accept the terms"),
  });

  try {
    // Validate request
    const { email, password, name, termsAccepted } = await schema.validate(
      req.body
    );

    // 🔁 Check for existing user by email
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .single();

    if (existingUser) {
      res.status(400).json({ error: "Email already registered" });
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const { data: newUser, error: insertError } = await supabase
      .from("users")
      .insert([
        {
          name,
          email,
          password: hashedPassword,
          termsAccepted,
        },
      ])
      .select("id, name, email, created_at")
      .single();

    if (insertError) {
      console.error("Insert Error:", insertError);
      res.status(500).json({ error: "Failed to register user" });
      return;
    }

    // Respond with success
    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        createdAt: newUser.created_at,
      },
    });
  } catch (error: any) {
    if (error.name === "ValidationError") {
      res
        .status(400)
        .json({ error: "Validation failed", details: error.errors });
    } else {
      console.error("Signup Error:", error);
      res.status(500).json({ error: "Server error during signup" });
    }
  }
};

// 📌 2️⃣ Login
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Search new user
    const user = await User.findOne({ where: { email } });
    if (!user) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    // ✅ Create JWT
    const token = jwt.sign({ id: user.id }, "your_secret_key", {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful!", token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
};
