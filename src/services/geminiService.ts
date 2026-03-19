import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export const analyzeThreat = async (content: string, type: 'log' | 'url' | 'code') => {
  const model = "gemini-3-flash-preview";
  const prompt = `You are a Senior Cyber Threat Intelligence Analyst. 
  Analyze the following ${type} and provide a detailed threat report in JSON format.
  Include:
  - severity (Low, Medium, High, Critical)
  - threatType (e.g., Malware, Phishing, Brute Force, etc.)
  - description
  - recommendations
  - confidenceScore (0-100)
  
  Content to analyze:
  ${content}`;

  try {
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });
    return JSON.parse(response.text || "{}");
  } catch (error) {
    console.error("Analysis failed:", error);
    return { error: "Failed to analyze threat" };
  }
};
