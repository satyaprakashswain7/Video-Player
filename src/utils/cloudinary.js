import { v2 as cloudinary } from "cloudinary";
import fs from "fs"
          
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.envCLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if(!localFilePath) return null
    const response = await cloudinary.uploader.upload(localFilePath,{
      resource_type : "auto"
    })
    //file has been uploaded successfully
    console.log("file has been uploaded on Cloidinary at : ",response.url);
    return response
  } catch (error) {
    fs.unlinkSync(localFilePath)
    //removes the temp file from the local server as uploading is failed
    return null
  }
}


export { uploadOnCloudinary }