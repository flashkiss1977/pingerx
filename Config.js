require('dotenv').config();

class Config {
    static mongo_uri = process.env.MONGO_URI || "mongodb+srv://flashkiss:fuck.you@cluster0.875emw9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
    static db_name = "flashkiss";
    static sites_collection = "sites";
    static config_collection = "app_config";
    static users_collection = "users";
    
    static telegram_bot_token = process.env.TELEGRAM_BOT_TOKEN || "Y8140590601:AAGgnKId_EGK3sVNY_gx2gU0ZARSRm7ZjgY";
    static telegram_chat_id = process.env.TELEGRAM_CHAT_ID || "7504667715";
    
    // Note: You'll need to create a new hash for your password using bcrypt
    static admin_password_hash = process.env.ADMIN_PASSWORD_HASH || "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi";
    
    static render_url = process.env.RENDER_URL || "https://pingerx-lap5.onrender.com";
    static ping_interval = 3600; // 1 hour in seconds
    static render_ping_interval = 25; // 25 seconds
    
    static scan_endpoint = "/Ghost.php?key=yuu_is_gay&action=scan";
}

module.exports = { Config };
