

export function generateOTP(){
    return Math.floor(100000 + Math.random() * 900000).toString();
}

export function getOtpHtml(otp){
    return `
        <h1>Verify your email</h1>
        <p>Your OTP is: <strong>${otp}</strong></p>
        <p>Please enter this code to verify your email address.</p>
    `;
}
