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
    
    // Add active class to clicked button
    event.target.classList.add('active');
}

function toggleHeader(enable) {
    headerEnabled = enable;
    
    const enableBtn = document.getElementById('enableBtn');
    const disableBtn = document.getElementById('disableBtn');
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
    const uploadBtn = document.getElementById('uploadBtn');
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
        resultBox.textContent = 'Click "Claim Your Prize!" to see how clickjacking tricks users into unintended actions...';
        resultBox.className = 'result-box result-info';
        document.getElementById('frameTechnicalDetails').style.display = 'none';
    }
}

function simulateClickjack() {
    const resultBox = document.getElementById('frameResultBox');
    const clickjackBtn = document.getElementById('clickjackBtn');
    const technicalDetails = document.getElementById('frameTechnicalDetails');
    const technicalExplanation = document.getElementById('frameTechnicalExplanation');
    
    clickjackBtn.disabled = true;
    clickjackBtn.textContent = 'Loading Prize...';
    
    setTimeout(() => {
        technicalDetails.style.display = 'block';
        
        if (frameProtectionEnabled) {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">🛡️</div>
                    <strong>CLICKJACKING BLOCKED!</strong><br>
                    The X-Frame-Options header prevented the malicious site from embedding the bank's page.
                    Users see an error instead of being tricked.
                </div>
            `;
            resultBox.className = 'result-box result-success';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Frame-Options: DENY is enabled<br>
                1. The malicious site tries to load the bank page in an invisible iframe<br>
                2. The browser receives the bank's response with X-Frame-Options: DENY header<br>
                3. The browser refuses to display the page within the iframe<br>
                4. Console shows: "Refused to display 'https://securebank.com' in a frame because it set 'X-Frame-Options' to 'deny'"<br>
                5. The clickjacking attack fails completely - users see nothing or an error message
            `;
            
        } else {
            resultBox.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 10px;">💀</div>
                    <strong>CLICKJACKING SUCCESSFUL!</strong><br>
                    The bank's page loaded invisibly! Users clicked "Transfer $5000" thinking it was a prize button.<br>
                    <small>Real impact: Money stolen → Accounts compromised → Customer trust destroyed</small>
                </div>
            `;
            resultBox.className = 'result-box result-danger';
            
            technicalExplanation.innerHTML = `
                <strong>Technical Details:</strong> When X-Frame-Options is missing<br>
                1. The malicious site successfully embeds the bank's page in an invisible iframe<br>
                2. The iframe is positioned exactly over the fake "prize" button<br>
                3. When users click the prize button, they actually click the bank's "Transfer Money" button<br>
                4. The bank processes the transfer because it's a legitimate click from a logged-in user<br>
                5. Users never see the bank interface - the attack happens completely invisibly
            `;
            
            setTimeout(() => {
                alert('🚨 CLICKJACKING ATTACK SIMULATED!\n\nYou just transferred $5000 to the attacker while trying to claim a prize!\n\nIn reality, this would happen without any visible indication.');
            }, 1000);
        }
        
        clickjackBtn.disabled = false;
        clickjackBtn.textContent = '🎁 Claim Your Prize! (Clickjacking Demo)';
    }, 1500);
}

// Update the DOMContentLoaded listener to initialize headers
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('disableBtn')) {
        toggleHeader(false);
    }
    if (document.getElementById('disableFrameBtn')) {
        toggleFrameProtection(false);
    }
});