const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const axios = require('axios');
const { Config } = require('./config');

class FlashKissPinger {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.mongo = null;
        this.db = null;
        this.sites = null;
        this.config = null;
        this.users = null;
        
        this.setupMiddleware();
        this.setupRoutes();
        this.initializeDatabase();
    }

    async initializeDatabase() {
        try {
            this.mongo = new MongoClient(Config.mongo_uri);
            await this.mongo.connect();
            this.db = this.mongo.db(Config.db_name);
            this.sites = this.db.collection(Config.sites_collection);
            this.config = this.db.collection(Config.config_collection);
            this.users = this.db.collection(Config.users_collection);
            
            await this.initializeCollections();
            console.log('Database connected successfully');
            
        } catch (error) {
            console.error('Database connection failed:', error);
            process.exit(1);
        }
    }

    async initializeCollections() {
        try {
            await this.sites.createIndex({ url: 1 }, { unique: true });
            await this.config.createIndex({ key: 1 }, { unique: true });
        } catch (error) {
            console.error('Error creating indexes:', error);
        }
    }

    setupMiddleware() {
        this.app.use(bodyParser.urlencoded({ extended: true }));
        this.app.use(bodyParser.json());
        this.app.use(session({
            secret: 'flashkiss-secret-key',
            resave: false,
            saveUninitialized: false,
            cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
        }));
        this.app.use(express.static('public'));
        this.app.set('view engine', 'ejs');
        
        // Run background tasks on every request
        this.app.use(async (req, res, next) => {
            await this.runBackgroundTasks();
            next();
        });
    }

    setupRoutes() {
        this.app.get('/', this.handleRoot.bind(this));
        this.app.post('/login', this.handleLogin.bind(this));
        this.app.get('/logout', this.handleLogout.bind(this));
        this.app.post('/add-site', this.handleAddSite.bind(this));
        this.app.post('/add-multiple-sites', this.handleAddMultipleSites.bind(this));
        this.app.post('/delete-site', this.handleDeleteSite.bind(this));
        this.app.post('/manual-scan', this.handleManualScan.bind(this));
        this.app.get('/async-scan', this.handleAsyncScan.bind(this));
    }

    // ==================== BACKGROUND TASKS ====================

    async runBackgroundTasks() {
        try {
            // 1. Always ping Render to keep alive
            await this.pingRender();
            
            // 2. Check if it's time to scan sites (every 1 hour)
            const last_scan = await this.getLastScanTime();
            if (Date.now() - last_scan >= Config.ping_interval * 1000) {
                this.runAsyncScan();
                await this.setLastScanTime(Date.now());
            }
        } catch (error) {
            console.error('Error in background tasks:', error);
        }
    }

    async getLastScanTime() {
        try {
            const config = await this.config.findOne({ key: 'last_scan' });
            return config ? config.value : 0;
        } catch (error) {
            console.error('Error getting last scan time:', error);
            return 0;
        }
    }

    async setLastScanTime(timestamp) {
        try {
            await this.config.updateOne(
                { key: 'last_scan' },
                { 
                    $set: { 
                        value: timestamp, 
                        updated_at: new Date() 
                    } 
                },
                { upsert: true }
            );
        } catch (error) {
            console.error('Error setting last scan time:', error);
        }
    }

    runAsyncScan() {
        const url = `${Config.render_url}?async_scan=1&key=${encodeURIComponent('yuu_is_gay')}`;
        
        axios.get(url, { timeout: 1000 })
            .catch(error => {
                // Ignore timeout errors for async scans
                if (error.code !== 'ECONNABORTED') {
                    console.error('Async scan error:', error.message);
                }
            });
    }

    // ==================== AUTHENTICATION ====================

    async login(password) {
        // For compatibility with PHP password_verify
        // In production, you should use a proper password comparison
        const isValid = await bcrypt.compare(password, Config.admin_password_hash);
        
        if (isValid) {
            this.app.locals.session = {
                authenticated: true,
                login_time: Date.now(),
                session_id: require('crypto').randomBytes(16).toString('hex')
            };
            return true;
        }
        return false;
    }

    logout(req) {
        req.session.destroy();
    }

    isAuthenticated(req) {
        return req.session.authenticated === true && req.session.session_id;
    }

    // ==================== SITE MANAGEMENT ====================

    async addSite(url, sessionId) {
        url = this.normalizeUrl(url);
        
        if (!this.isValidUrl(url)) {
            return { success: false, message: 'Invalid URL format' };
        }

        try {
            const existing = await this.sites.findOne({ url });
            if (existing) {
                return { success: false, message: 'Site already exists' };
            }

            const site = {
                url,
                added_at: new Date(),
                last_scan: null,
                status: 'active',
                response_time: null,
                last_status: 'pending',
                scan_count: 0,
                created_by: sessionId || 'system'
            };

            const result = await this.sites.insertOne(site);
            
            if (result.insertedCount > 0) {
                return { success: true, message: 'Site added successfully' };
            }
        } catch (error) {
            return { success: false, message: 'Database error: ' + error.message };
        }

        return { success: false, message: 'Failed to add site' };
    }

    async addMultipleSites(urlsText, sessionId) {
        const urls = urlsText.split('\n')
            .map(url => url.trim())
            .filter(url => url.length > 0);

        const results = {
            success: 0,
            failed: 0,
            messages: []
        };

        for (const url of urls) {
            const result = await this.addSite(url, sessionId);
            if (result.success) {
                results.success++;
            } else {
                results.failed++;
                results.messages.push(`${url}: ${result.message}`);
            }
        }

        return results;
    }

    async deleteSite(siteId) {
        try {
            const result = await this.sites.deleteOne({ _id: new ObjectId(siteId) });
            return result.deletedCount > 0;
        } catch (error) {
            console.error('Error deleting site:', error);
            return false;
        }
    }

    async getAllSites() {
        try {
            return await this.sites.find({}).sort({ added_at: -1 }).toArray();
        } catch (error) {
            console.error('Error getting sites:', error);
            return [];
        }
    }

    async getSiteCount() {
        try {
            return await this.sites.countDocuments();
        } catch (error) {
            console.error('Error counting sites:', error);
            return 0;
        }
    }

    async getStats() {
        try {
            const total_sites = await this.sites.countDocuments();
            const active_sites = await this.sites.countDocuments({ status: 'active' });
            
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            const scanned_today = await this.sites.countDocuments({
                last_scan: { $gte: today }
            });

            return {
                total_sites,
                active_sites,
                scanned_today
            };
        } catch (error) {
            return { total_sites: 0, active_sites: 0, scanned_today: 0 };
        }
    }

    // ==================== SCANNING ====================

    async scanAllSites() {
        try {
            const sites = await this.sites.find({ status: 'active' }).toArray();
            const results = [];

            for (const site of sites) {
                const result = await this.scanSite(site);
                results.push(result);

                await this.updateSiteAfterScan(site._id, result);

                if (result.status === 'access_denied') {
                    await this.sendAccessDeniedAlert(site.url);
                }

                await new Promise(resolve => setTimeout(resolve, 500));
            }

            return results;
        } catch (error) {
            console.error('Error scanning all sites:', error);
            return [];
        }
    }

    async scanSite(site) {
        const start_time = Date.now();
        const scan_url = site.url + Config.scan_endpoint;

        try {
            const response = await axios.get(scan_url, {
                timeout: 30000,
                headers: {
                    'User-Agent': 'FlashKiss-Security-Monitor/1.0'
                },
                validateStatus: () => true
            });

            const end_time = Date.now();
            const response_time = (end_time - start_time) / 1000;

            if (response.status === 200) {
                const data = response.data;
                return {
                    url: site.url,
                    status: data.status || 'unknown',
                    response_time: parseFloat(response_time.toFixed(2)),
                    suspicious_found: data.suspicious_found || 0,
                    http_code: response.status,
                    success: true
                };
            } else if (response.status === 403) {
                return {
                    url: site.url,
                    status: 'access_denied',
                    response_time: parseFloat(response_time.toFixed(2)),
                    http_code: response.status,
                    error: 'Access Denied - Script may be deleted',
                    success: false
                };
            } else {
                return {
                    url: site.url,
                    status: 'error',
                    response_time: parseFloat(response_time.toFixed(2)),
                    http_code: response.status,
                    error: `HTTP ${response.status}`,
                    success: false
                };
            }
        } catch (error) {
            return {
                url: site.url,
                status: 'error',
                response_time: (Date.now() - start_time) / 1000,
                error: error.message,
                success: false
            };
        }
    }

    async updateSiteAfterScan(siteId, result) {
        try {
            const update_data = {
                last_scan: new Date(),
                response_time: result.response_time,
                last_status: result.status
            };

            if (result.success) {
                update_data.$inc = { scan_count: 1 };
            }

            await this.sites.updateOne(
                { _id: siteId },
                { $set: update_data }
            );
        } catch (error) {
            console.error('Error updating site after scan:', error);
        }
    }

    // ==================== TELEGRAM ALERTS ====================

    async sendAccessDeniedAlert(website_url) {
        const message = "🚨 *Message From FlashKiss Server*\n\n" +
            "🌐 *Website:* `" + website_url + "`\n" +
            "❌ *Issue:* Our System Did Not Connect With `" + website_url + "`. My Brain Sorry My Developer I Mean Flashkiss Told To You Maybe Site Owner OR Any MotherFucker Delete Our Main Script Kindly Check.\n\n" +
            "🕒 *Time:* " + new Date().toLocaleString();

        await this.sendTelegramMessage(message);
    }

    async sendTelegramMessage(message) {
        const url = `https://api.telegram.org/bot${Config.telegram_bot_token}/sendMessage`;
        const data = {
            chat_id: Config.telegram_chat_id,
            text: message,
            parse_mode: 'Markdown',
            disable_web_page_preview: true
        };

        try {
            await axios.post(url, data, { timeout: 10000 });
        } catch (error) {
            console.error('Error sending Telegram message:', error);
        }
    }

    // ==================== RENDER PING ====================

    async pingRender() {
        try {
            const response = await axios.get(Config.render_url, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'FlashKiss-Pinger/1.0'
                }
            });

            await this.config.updateOne(
                { key: 'last_ping' },
                {
                    $set: {
                        value: Date.now(),
                        http_code: response.status,
                        updated_at: new Date()
                    }
                },
                { upsert: true }
            );

            return response.status === 200;
        } catch (error) {
            console.error('Render ping failed:', error.message);
            return false;
        }
    }

    // ==================== UTILITY FUNCTIONS ====================

    normalizeUrl(url) {
        url = url.trim();
        if (!/^(?:f|ht)tps?:\/\//i.test(url)) {
            url = "https://" + url;
        }
        return url.replace(/\/+$/, '');
    }

    isValidUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    // ==================== ROUTE HANDLERS ====================

    async handleRoot(req, res) {
        if (this.isAuthenticated(req)) {
            const stats = await this.getStats();
            const sites = await this.getAllSites();
            
            res.render('dashboard', {
                stats,
                sites,
                messages: req.session.messages,
                errors: req.session.errors
            });
            
            delete req.session.messages;
            delete req.session.errors;
        } else {
            res.render('login', { error: req.query.error });
        }
    }

    async handleLogin(req, res) {
        const { password } = req.body;
        
        if (await this.login(password)) {
            req.session.authenticated = true;
            req.session.login_time = Date.now();
            req.session.session_id = require('crypto').randomBytes(16).toString('hex');
            res.redirect('/');
        } else {
            res.redirect('/?error=1');
        }
    }

    handleLogout(req, res) {
        this.logout(req);
        res.redirect('/');
    }

    async handleAddSite(req, res) {
        if (!this.isAuthenticated(req)) {
            return res.redirect('/');
        }

        const { single_url } = req.body;
        const result = await this.addSite(single_url, req.session.session_id);
        
        req.session.messages = result.success ? [result.message] : [];
        req.session.errors = result.success ? [] : [result.message];
        res.redirect('/');
    }

    async handleAddMultipleSites(req, res) {
        if (!this.isAuthenticated(req)) {
            return res.redirect('/');
        }

        const { multiple_urls } = req.body;
        const result = await this.addMultipleSites(multiple_urls, req.session.session_id);
        
        req.session.messages = [`Added ${result.success} sites, failed: ${result.failed}`];
        if (result.messages.length > 0) {
            req.session.errors = result.messages.slice(0, 5);
        }
        res.redirect('/');
    }

    async handleDeleteSite(req, res) {
        if (!this.isAuthenticated(req)) {
            return res.redirect('/');
        }

        const { site_id } = req.body;
        const success = await this.deleteSite(site_id);
        
        req.session.messages = success ? ['Site deleted successfully'] : [];
        req.session.errors = success ? [] : ['Failed to delete site'];
        res.redirect('/');
    }

    async handleManualScan(req, res) {
        if (!this.isAuthenticated(req)) {
            return res.redirect('/');
        }

        const results = await this.scanAllSites();
        const scanned = results.filter(r => r.success).length;
        const failed = results.length - scanned;
        
        req.session.messages = [`Manual scan completed. Scanned: ${scanned}, Failed: ${failed}`];
        res.redirect('/');
    }

    async handleAsyncScan(req, res) {
        if (req.query.async_scan && req.query.key === 'yuu_is_gay') {
            await this.scanAllSites();
            res.send('Async scan completed');
        } else {
            res.status(403).send('Forbidden');
        }
    }

    start() {
        this.app.listen(this.port, () => {
            console.log(`FlashKiss Pinger running on port ${this.port}`);
        });
    }
}

// Start the application
const app = new FlashKissPinger();

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down...');
    if (app.mongo) {
        await app.mongo.close();
    }
    process.exit(0);
});

module.exports = FlashKissPinger;