// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyDrb-gGxhvNZdwTepqslB6OgdEnIY-DHyg",
  authDomain: "sas-seat-allotment.firebaseapp.com",
  projectId: "sas-seat-allotment",
  storageBucket: "sas-seat-allotment.firebasestorage.app",
  messagingSenderId: "801027790525",
  appId: "1:801027790525:web:a9a3cfa9b9142f7b4509d4",
  measurementId: "G-QMXRDBQ2NM"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

// Function to sign in with Google
export const signInWithGoogle = async () => {
  try {
    return await signInWithPopup(auth, googleProvider);
  } catch (error) {
    console.error("Error during Google sign-in:", error);
    throw error;
  }
};

export { auth };
