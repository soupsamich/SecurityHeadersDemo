// X-CONTENT-TYPE-OPTIONS
let headerEnabled = false;

function showTab(tabId) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabId).classList.add('active');
    
    // Find and activate the correct button by checking the onclick attribute
    document.querySelectorAll('.tab-button').forEach(btn => {
        if (btn.getAttribute('onclick') === `showTab('${tabId}')`) {
            btn.classList.add('active');
        }
    });
    
    // Scroll to top of page
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

function toggleHeader(enable) {
    headerEnabled = enable;
    
    const enableBtn = document.getElementById('enableContentBtn');
    const disableBtn = document.getElementById('disableContentBtn');
    const statusIcon = document.getElementById('statusIcon');
    const statusText = document.getElementById('statusText');
    const headerStatus = document.getElementById('headerStatus');
    const resultBox = document.getElementById('resultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'X-Content-Type-Options: nosniff (Protected)';
        headerStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'Protection enabled. Upload simulation will now show how the header blocks malicious execution.';
        resultBox.className = 'result-box result-info';
        document.getElementById('technicalDetails').style.display = 'none'; // Hide technical details
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'X-Content-Type-Options: DISABLED (Vulnerable)';
        headerStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Click "Upload Malicious File" to see what happens when someone visits this file...';
        resultBox.className = 'result-box result-info';
        document.getElementById('technicalDetails').style.display = 'none'; // Hide technical details
    }
}

function simulateUpload() {
    const resultBox = document.getElementById('resultBox');
    const uploadBtn = document.getElementById('uploadFileBtn');
    const technicalDetails = document.getElementById('technicalDetails');
    const technicalExplanation = document.getElementById('technicalExplanation');
    
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Uploading...';
    
    setTimeout(() => {
        // Show technical details section
        technicalDetails.style.display = 'block';
        
        if (headerEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>ATTACK BLOCKED!</strong><br>
                    The X-Content-Type-Options header prevented the browser from executing the malicious script.
                    The file is safely treated as plain text only.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Content-Type-Options: nosniff is enabled<br>
                1. The server responds with Content-Type: text/plain AND X-Content-Type-Options: nosniff<br>
                2. The browser sees the nosniff header and refuses to MIME-sniff the content<br>
                3. The &lt;script&gt; tag fails to load because the browser won't treat text/plain as JavaScript<br>
                4. Within the console you'll see an error like: "Refused to execute script from 'team-updates.txt' because its MIME type ('text/plain') is not executable"<br>
                5. The script tag's onerror event fires
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>ATTACK SUCCESSFUL!</strong><br>
                    Without the header, the browser executed the malicious JavaScript!<br>
                    <small>In a real attack: Session stolen → Data exfiltrated → Admin access gained</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Content-Type-Options is missing<br>
                1. The server responds with only Content-Type: text/plain (no nosniff header)<br>
                2. The browser performs MIME-sniffing and detects JavaScript-like content<br>
                3. The browser overrides the declared MIME type and treats the file as JavaScript<br>
                4. The &lt;script&gt; tag loads successfully and executes the malicious code<br>
                5. In a real attack, this would steal cookies, sessions, or sensitive data silently
            `;
            
            // Simulate the actual attack effect
            if (!window.attackSimulated) {
                setTimeout(() => {
                    alert('🚨 SIMULATED ATTACK: Your session would be stolen!\n\nIn reality, this would happen silently in the background.');
                }, 1000);
            }
        }
        
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload Malicious File';
    }, 1500);
}

// X-FRAME-OPTIONS
let frameProtectionEnabled = false;

function toggleFrameProtection(enable) {
    frameProtectionEnabled = enable;
    
    const enableBtn = document.getElementById('enableFrameBtn');
    const disableBtn = document.getElementById('disableFrameBtn');
    const statusIcon = document.getElementById('frameStatusIcon');
    const statusText = document.getElementById('frameStatusText');
    const frameStatus = document.getElementById('frameStatus');
    const resultBox = document.getElementById('frameResultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'X-Frame-Options: DENY (Protected)';
        frameStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'Frame protection enabled. Clickjacking attempts will now be blocked.';
        resultBox.className = 'result-box result-info';
        document.getElementById('frameTechnicalDetails').style.display = 'none';
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'X-Frame-Options: DISABLED (Vulnerable)';
        frameStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Enter a number and click "Claim Your Prize!" to see how clickjacking tricks users into unintended actions...';
        resultBox.className = 'result-box result-info';
        document.getElementById('frameTechnicalDetails').style.display = 'none';
    }
}

function simulateClickjack() {
    const resultBox = document.getElementById('frameResultBox');
    const clickjackBtn = document.getElementById('clickjackBtn');
    const technicalDetails = document.getElementById('frameTechnicalDetails');
    const technicalExplanation = document.getElementById('frameTechnicalExplanation');
    const prizeInput = document.getElementById('prizeGuess');
    
    // Get the amount entered by the user
    const enteredAmount = prizeInput.value;
    
    // Validate input
    if (!enteredAmount || enteredAmount < 5000 || enteredAmount > 10000) {
        alert('Please enter a number between 5000 and 10000 to continue with the demo!');
        return;
    }
    
    clickjackBtn.disabled = true;
    clickjackBtn.textContent = 'Processing Prize...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (frameProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>CLICKJACKING BLOCKED!</strong><br>
                    The X-Frame-Options header prevented the malicious site from embedding the bank's page.
                    Your number ${enteredAmount} was safely entered into a harmless form.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Frame-Options: DENY is enabled<br>
                1. The malicious site tries to load the bank page in an invisible iframe<br>
                2. The browser receives the bank's response with X-Frame-Options: DENY header<br>
                3. The browser refuses to display the page within the iframe<br>
                4. Console shows: "Refused to display 'https://securebank.com' in a frame because it set 'X-Frame-Options' to 'deny'"<br>
                5. The clickjacking attack fails completely - users see nothing or an error message<br>
                6. Your entered number (${enteredAmount}) stays safely in the prize form
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>CLICKJACKING SUCCESSFUL!</strong><br>
                    The bank's page loaded invisibly! You just transferred \$${enteredAmount} to the attacker while thinking you were entering a prize guess!<br>
                    <small>Real impact: Money stolen → Accounts compromised → Customer trust destroyed</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Frame-Options is missing<br>
                1. The malicious site successfully embeds the bank's page in an invisible iframe<br>
                2. Your "prize guess" of ${enteredAmount} was actually entered into the hidden bank's transfer amount field<br>
                3. The iframe is positioned exactly over the fake "prize" button and input field<br>
                4. When you clicked "Claim Prize", you actually clicked the bank's "Transfer Money" button<br>
                5. The bank processes the ${enteredAmount} transfer because it's a legitimate click from a logged-in user<br>
                6. You never see the bank interface - the attack happens completely invisibly
            `;
            
            setTimeout(() => {
                alert(`🚨 CLICKJACKING ATTACK SIMULATED!\n\nYou just transferred \$${enteredAmount} to the attacker while trying to claim a prize!\n\nThe number you thought was your "lucky guess" was actually the transfer amount!\n\nIn reality, this would happen without any visible indication.`);
            }, 1000);
        }
        
        clickjackBtn.disabled = false;
        clickjackBtn.textContent = '🎁 Claim Your Prize! (Clickjacking Demo)';
    }, 1500);
}

// CONTENT-SECURITY-POLICY
let cspProtectionEnabled = false;

function toggleCSPProtection(enable) {
    cspProtectionEnabled = enable;
    
    const enableBtn = document.getElementById('enableCSPBtn');
    const disableBtn = document.getElementById('disableCSPBtn');
    const statusIcon = document.getElementById('cspStatusIcon');
    const statusText = document.getElementById('cspStatusText');
    const cspStatus = document.getElementById('cspStatus');
    const resultBox = document.getElementById('cspResultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'Content-Security-Policy: script-src \'self\' (Protected)';
        cspStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'CSP protection enabled. XSS attempts will now be blocked.';
        resultBox.className = 'result-box result-info';
        document.getElementById('cspTechnicalDetails').style.display = 'none';
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'Content-Security-Policy: DISABLED (Vulnerable)';
        cspStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Enter a review and click "Submit Review" to see how XSS attacks work...';
        resultBox.className = 'result-box result-info';
        document.getElementById('cspTechnicalDetails').style.display = 'none';
    }
}

function simulateXSS() {
    const resultBox = document.getElementById('cspResultBox');
    const submitBtn = document.getElementById('submitReviewBtn');
    const technicalDetails = document.getElementById('cspTechnicalDetails');
    const technicalExplanation = document.getElementById('cspTechnicalExplanation');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Loading Review...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (cspProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>XSS ATTACK BLOCKED!</strong><br>
                    Content-Security-Policy prevented the malicious script from executing.
                    Users see only the review text, script tags are blocked.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Content-Security-Policy is enabled<br>
                1. The malicious review is loaded on the product page<br>
                2. CSP header is sent: script-src 'self'<br>
                3. Browser sees the &lt;script&gt; tag in the review content<br>
                4. CSP blocks execution because inline scripts are not in the allowlist<br>
                5. Console shows: "Refused to execute inline script because it violates CSP"<br>
                6. Users only see the review text - the malicious script fails silently
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>XSS ATTACK SUCCESSFUL!</strong><br>
                    The malicious script executed when users viewed this review!<br>
                    <small>Real impact: User data stolen → Accounts compromised → Malware distributed</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Content-Security-Policy is missing<br>
                1. The malicious review loads on the product page<br>
                2. Browser processes the HTML content including script tags<br>
                3. No CSP header means no restrictions on script execution<br>
                4. The &lt;script&gt; tag executes immediately in visitors' browsers<br>
                5. User data is stolen and sent to attacker-controlled servers<br>
                6. This happens silently to every user who views this review
            `;
            
            setTimeout(() => {
                alert('🚨 XSS ATTACK SIMULATED!\n\nThe malicious script in the review just executed!\n\nIn reality, this would:\n• Steal user login sessions\n• Extract personal and payment data\n• Redirect to malware sites\n• Happen silently to every user who views this review');
            }, 1000);
        }
        
        submitBtn.disabled = false;
        submitBtn.textContent = '👁️ View Malicious Review (Simulate XSS)';
    }, 1500);
}

// STRICT-TRANSPORT-SECURITY
let hstsProtectionEnabled = false;

function toggleHSTSProtection(enable) {
    hstsProtectionEnabled = enable;
    
    const enableBtn = document.getElementById('enableHSTSBtn');
    const disableBtn = document.getElementById('disableHSTSBtn');
    const statusIcon = document.getElementById('hstsStatusIcon');
    const statusText = document.getElementById('hstsStatusText');
    const hstsStatus = document.getElementById('hstsStatus');
    const resultBox = document.getElementById('hstsResultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'Strict-Transport-Security: max-age=31536000 (Protected)';
        hstsStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'HSTS protection enabled. SSL stripping attacks will now be blocked.';
        resultBox.className = 'result-box result-info';
        document.getElementById('hstsTechnicalDetails').style.display = 'none';
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'Strict-Transport-Security: DISABLED (Vulnerable)';
        hstsStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Click "Connect to Bank" to see how SSL stripping attacks work...';
        resultBox.className = 'result-box result-info';
        document.getElementById('hstsTechnicalDetails').style.display = 'none';
    }
}

function simulateSSLStrip() {
    const resultBox = document.getElementById('hstsResultBox');
    const connectBtn = document.getElementById('connectBankBtn');
    const technicalDetails = document.getElementById('hstsTechnicalDetails');
    const technicalExplanation = document.getElementById('hstsTechnicalExplanation');
    
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (hstsProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>SSL STRIPPING BLOCKED!</strong><br>
                    HSTS prevented the browser from connecting over insecure HTTP.
                    Your connection remains secure and encrypted.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When HSTS is enabled<br>
                1. Browser attempts to connect to trusted-bank.com<br>
                2. Browser checks its HSTS cache and finds the domain<br>
                3. Browser automatically upgrades any HTTP request to HTTPS<br>
                4. Even if attacker tries SSL stripping, browser refuses HTTP connection<br>
                5. Browser shows security error rather than connecting insecurely<br>
                6. User's banking credentials remain protected by encryption
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>SSL STRIPPING SUCCESSFUL!</strong><br>
                    Your connection was downgraded to insecure HTTP! Banking credentials stolen!<br>
                    <small>Real impact: Financial theft → Identity theft → Account takeover</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When HSTS is missing<br>
                1. Browser attempts to connect to trusted-bank.com<br>
                2. Attacker's proxy intercepts the connection request<br>
                3. Attacker strips HTTPS and redirects to HTTP version<br>
                4. Browser connects over unencrypted HTTP without warning<br>
                5. All login credentials are transmitted in plain text<br>
                6. Attacker captures username, password, and session data
            `;
            
            setTimeout(() => {
                alert('🚨 SSL STRIPPING ATTACK SIMULATED!\n\nYour banking login was intercepted over insecure HTTP!\n\nIn reality, this would:\n• Steal your username and password\n• Capture your account numbers\n• Allow unauthorized transfers\n• Happen without any visible warning');
            }, 1000);
        }
        
        connectBtn.disabled = false;
        connectBtn.textContent = '🔗 Connect to Bank (Simulate Attack)';
    }, 1500);
}
// REFERRER POLICY
let referrerProtectionEnabled = false;

function toggleReferrerProtection(enable) {
    referrerProtectionEnabled = enable;
    
    const enableBtn = document.getElementById('enableRefPolBtn');
    const disableBtn = document.getElementById('disableRefPolBtn');
    const statusIcon = document.getElementById('refpolStatusIcon');
    const statusText = document.getElementById('refpolStatusText');
    const refpolStatus = document.getElementById('refpolStatus');
    const resultBox = document.getElementById('refpolResultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'Referrer-Policy: strict-origin-when-cross-origin (Protected)';
        refpolStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'Referrer protection enabled. Sensitive URL information will be protected.';
        resultBox.className = 'result-box result-info';
        document.getElementById('refpolTechnicalDetails').style.display = 'none';
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'Referrer-Policy: DISABLED (Vulnerable)';
        refpolStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Click the external link to see what referrer information gets leaked...';
        resultBox.className = 'result-box result-info';
        document.getElementById('refpolTechnicalDetails').style.display = 'none';
    }
}

function simulateReferrerLeak() {
    const resultBox = document.getElementById('refpolResultBox');
    const clickBtn = document.getElementById('clickLinkBtn');
    const technicalDetails = document.getElementById('refpolTechnicalDetails');
    const technicalExplanation = document.getElementById('refpolTechnicalExplanation');
    
    clickBtn.disabled = true;
    clickBtn.textContent = 'Navigating to external site...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (referrerProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>REFERRER INFORMATION PROTECTED!</strong><br>
                    Referrer Policy prevented sensitive URL information from leaking.
                    External site only received the domain name, not the full path.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Referrer-Policy is enabled<br>
                1. User clicks external link from sensitive medical records page<br>
                2. Browser checks Referrer-Policy: strict-origin-when-cross-origin<br>
                3. Since it's a cross-origin request (different domain), only origin is sent<br>
                4. External site receives: "Referer: https://healthsecure.com" (just domain)<br>
                5. Sensitive URL parameters (patient ID, session token, medical data) are stripped<br>
                6. Patient privacy is protected while link functionality still works
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>SENSITIVE INFORMATION LEAKED!</strong><br>
                    The external pharmacy site received the full URL with patient ID, session token, and medical test results!<br>
                    <small>Real impact: Privacy violations → Medical discrimination → Identity theft</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Referrer-Policy is missing<br>
                1. User clicks external link from medical records page<br>
                2. Browser sends full referrer URL by default<br>
                3. External site receives complete URL with sensitive parameters<br>
                4. Pharmacy site now knows: patient ID (12345), session token (abc123), medical results (hiv-test-positive)<br>
                5. This information can be logged, sold to data brokers, or used for targeted advertising<br>
                6. Patient's medical privacy is completely compromised
            `;
            
            setTimeout(() => {
                alert('🚨 REFERRER LEAKAGE SIMULATED!\n\nThe pharmacy website just received your full medical URL!\n\nThey now know:\n• Your patient ID\n• Your session token\n• Your HIV test results\n• Your doctor\'s name\n\nIn reality, this data could be:\n• Sold to advertisers\n• Used for medical discrimination\n• Exploited for identity theft');
            }, 1000);
        }
        
        clickBtn.disabled = false;
        clickBtn.textContent = '💊 Click External Pharmacy Link';
    }, 1500);
}

// PERMISSIONS POLICY
let permissionsProtectionEnabled = false;

function togglePermissionsProtection(enable) {
    permissionsProtectionEnabled = enable;
    
    const enableBtn = document.getElementById('enablePermPolBtn');
    const disableBtn = document.getElementById('disablePermPolBtn');
    const statusIcon = document.getElementById('permpolStatusIcon');
    const statusText = document.getElementById('permpolStatusText');
    const permpolStatus = document.getElementById('permpolStatus');
    const resultBox = document.getElementById('permpolResultBox');

    if (enable) {
        enableBtn.disabled = true;
        disableBtn.disabled = false;
        statusIcon.textContent = '🛡️';
        statusText.textContent = 'Permissions-Policy: camera=(), microphone=() (Protected)';
        permpolStatus.className = 'status-indicator status-protected';
        resultBox.textContent = 'Permissions protection enabled. Third-party feature access will be blocked.';
        resultBox.className = 'result-box result-info';
        document.getElementById('permpolTechnicalDetails').style.display = 'none';
    } else {
        enableBtn.disabled = false;
        disableBtn.disabled = true;
        statusIcon.textContent = '🚨';
        statusText.textContent = 'Permissions-Policy: DISABLED (Vulnerable)';
        permpolStatus.className = 'status-indicator status-vulnerable';
        resultBox.textContent = 'Click "Load Page" to see what happens when ads try to access device features...';
        resultBox.className = 'result-box result-info';
        document.getElementById('permpolTechnicalDetails').style.display = 'none';
    }
}

function simulatePermissionsAbuse() {
    const resultBox = document.getElementById('permpolResultBox');
    const loadBtn = document.getElementById('loadAdBtn');
    const technicalDetails = document.getElementById('permpolTechnicalDetails');
    const technicalExplanation = document.getElementById('permpolTechnicalExplanation');
    
    loadBtn.disabled = true;
    loadBtn.textContent = 'Loading page and ads...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (permissionsProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>PERMISSIONS ACCESS BLOCKED!</strong><br>
                    Permissions Policy prevented the malicious ad from accessing camera, microphone, and precise location.
                    Users remain protected from unauthorized surveillance.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Permissions-Policy is enabled<br>
                1. Malicious ad attempts to access navigator.mediaDevices.getUserMedia()<br>
                2. Browser checks Permissions-Policy header: camera=(), microphone=()<br>
                3. Empty allowlist means no origins can access these features<br>
                4. Browser blocks the API calls and returns permission denied errors<br>
                5. Ad cannot activate camera/microphone or access precise geolocation<br>
                6. User privacy is protected while legitimate site features still work
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>DEVICE FEATURES COMPROMISED!</strong><br>
                    The malicious ad gained access to camera, microphone, and location! Secret surveillance is now active!<br>
                    <small>Real impact: Privacy violations → Surveillance → Stalking → Blackmail</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When Permissions-Policy is missing<br>
                1. Malicious ad loads within the trusted news website context<br>
                2. Ad script calls navigator.mediaDevices.getUserMedia() for camera/microphone<br>
                3. No Permissions Policy means browser uses default permissive behavior<br>
                4. User may see permission prompts, but they appear to come from "trusted news site"<br>
                5. If granted, ad gains full access to camera/microphone streams<br>
                6. Surveillance data is secretly transmitted to attacker-controlled servers
            `;
            
            setTimeout(() => {
                alert('🚨 PERMISSIONS ABUSE SIMULATED!\n\nThe advertisement just gained access to your:\n• Camera (now recording video)\n• Microphone (now recording audio)\n• Precise GPS location\n• Device battery/performance\n\nIn reality, this would:\n• Record you without indication\n• Track your exact movements\n• Sell surveillance data\n• Operate continuously in background');
            }, 1000);
        }
        
        loadBtn.disabled = false;
        loadBtn.textContent = '📰 Load Page with Malicious Ad';
    }, 1500);
}

// QUIZ FUNCTIONALITY
const quizAnswers = {
    q1: 'xcto',
    q2: 'hsts', 
    q3: 'xfo',
    q4: 'refpol',
    q5: 'csp',
    q6: 'permpol'
};

const quizExplanations = {
    q1: {
        correct: "X-Content-Type-Options prevents browsers from MIME-sniffing and executing files with mismatched content types.",
        incorrect: "X-Content-Type-Options is correct. It prevents browsers from treating .txt files as executable JavaScript."
    },
    q2: {
        correct: "Strict-Transport-Security forces browsers to only use HTTPS connections, preventing SSL stripping attacks.",
        incorrect: "Strict-Transport-Security is correct. It prevents downgrade attacks from HTTPS to HTTP."
    },
    q3: {
        correct: "X-Frame-Options prevents websites from being embedded in iframes, stopping clickjacking attacks.",
        incorrect: "X-Frame-Options is correct. It prevents malicious sites from embedding your pages invisibly."
    },
    q4: {
        correct: "Referrer-Policy controls what URL information is sent to external sites when users click links.",
        incorrect: "Referrer-Policy is correct. It prevents sensitive URL parameters from leaking to external sites."
    },
    q5: {
        correct: "Content-Security-Policy provides the strongest defense against XSS attacks by controlling script execution.",
        incorrect: "Content-Security-Policy is correct. It's the primary defense against cross-site scripting attacks."
    },
    q6: {
        correct: "Permissions-Policy controls which browser features like camera and microphone can be accessed by third-party content.",
        incorrect: "Permissions-Policy is correct. It prevents unauthorized access to device features like camera and microphone."
    }
};

function submitQuiz() {
    const form = document.getElementById('quizForm');
    const formData = new FormData(form);
    let score = 0;
    let totalQuestions = Object.keys(quizAnswers).length;
    
    // Check each answer
    for (let [question, correctAnswer] of Object.entries(quizAnswers)) {
        const userAnswer = formData.get(question);
        const feedbackElement = document.getElementById(`feedback${question.slice(1)}`);
        
        if (userAnswer === correctAnswer) {
            score++;
            feedbackElement.className = 'quiz-feedback correct';
            feedbackElement.innerHTML = `✅ Correct! ${quizExplanations[question].correct}`;
        } else {
            feedbackElement.className = 'quiz-feedback incorrect';
            feedbackElement.innerHTML = `❌ Incorrect. ${quizExplanations[question].incorrect}`;
        }
        
        feedbackElement.style.display = 'block';
    }
    
    // Show results
    const resultsElement = document.getElementById('quizResults');
    const scoreElement = document.getElementById('scoreDisplay');
    const messageElement = document.getElementById('scoreMessage');
    
    const percentage = Math.round((score / totalQuestions) * 100);
    scoreElement.textContent = `Your Score: ${score}/${totalQuestions} (${percentage}%)`;
    
    let message = '';
    if (percentage >= 90) {
        message = '🏆 Outstanding! You have an excellent understanding of security headers.';
    } else if (percentage >= 80) {
        message = '🎉 Great job! You have a solid grasp of security header concepts.';
    } else if (percentage >= 70) {
        message = '👍 Good work! Review the incorrect answers to strengthen your knowledge.';
    } else if (percentage >= 60) {
        message = '📚 Not bad! Consider reviewing the security header lessons again.';
    } else {
        message = '🔄 You might want to go through the security header tutorials once more.';
    }
    
    messageElement.textContent = message;
    resultsElement.style.display = 'block';
    
    // Show reset button and hide submit button
    document.querySelector('button[onclick="submitQuiz()"]').style.display = 'none';
    document.getElementById('resetBtn').style.display = 'inline-block';
    
    // Disable form inputs
    const inputs = form.querySelectorAll('input[type="radio"]');
    inputs.forEach(input => input.disabled = true);
}

function resetQuiz() {
    const form = document.getElementById('quizForm');
    
    // Reset form
    form.reset();
    
    // Hide all feedback
    document.querySelectorAll('.quiz-feedback').forEach(feedback => {
        feedback.style.display = 'none';
    });
    
    // Hide results
    document.getElementById('quizResults').style.display = 'none';
    
    // Show submit button and hide reset button
    document.querySelector('button[onclick="submitQuiz()"]').style.display = 'inline-block';
    document.getElementById('resetBtn').style.display = 'none';
    
    // Re-enable form inputs
    const inputs = form.querySelectorAll('input[type="radio"]');
    inputs.forEach(input => input.disabled = false);
    
    // Scroll to top of quiz
    document.getElementById('quiz').scrollIntoView({ behavior: 'smooth' });
}

// EVENT LISTENER
document.addEventListener('DOMContentLoaded', function() {
    // Initialize home tab as default
    if (document.getElementById('home')) {
        showTab('home');
    }
    // Toggle on/off header buttons
    if (document.getElementById('disableContentBtn')) {
        toggleHeader(false);
    }
    if (document.getElementById('disableFrameBtn')) {
        toggleFrameProtection(false);
    }
    if (document.getElementById('disableCSPBtn')) {
        toggleCSPProtection(false);
    }
    if (document.getElementById('disableHSTSBtn')) {
        toggleHSTSProtection(false);
    }
    if (document.getElementById('disableRefPolBtn')) {
    toggleReferrerProtection(false);
    }
    if (document.getElementById('disablePermPolBtn')) {
    togglePermissionsProtection(false);
    }
    
    // For XFO tab: Add input validation for prize guess
    const prizeInput = document.getElementById('prizeGuess');
    if (prizeInput) {
        prizeInput.addEventListener('input', function() {
            const value = parseInt(this.value);
            if (value && (value < 5000 || value > 10000)) {
                this.style.borderColor = '#e74c3c';
                this.style.backgroundColor = '#fdf2f2';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });
        
        // Add some visual feedback when user types for 
        prizeInput.addEventListener('keyup', function() {
            const value = parseInt(this.value);
            if (value >= 5000 && value <= 10000) {
                this.style.borderColor = '#27ae60';
                this.style.backgroundColor = '#f8fff8';
            }
        });
    }
});
