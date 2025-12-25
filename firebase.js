import admin from "firebase-admin";
import "dotenv/config";

const serviceAccount = {
  projectId: "zta-deviceregistry",
  clientEmail: "firebase-adminsdk@zta-deviceregistry.iam.gserviceaccount.com",
  privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://zta-deviceregistry-default-rtdb.firebaseio.com/"
});

export const db = admin.database();
