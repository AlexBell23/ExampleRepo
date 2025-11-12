
// script.js - Settings functionality

// Initialize settings when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeSettings();
    loadSavedSettings();
});

// Initialize all settings controls
function initializeSettings() {
    // Dark mode toggle
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', toggleDarkMode);
    }
    
    // Font size selector
    const fontSizeSelect = document.getElementById('font-size-select');
    if (fontSizeSelect) {
        fontSizeSelect.addEventListener('change', changeFontSize);
    }
}

// Load saved settings from localStorage
function loadSavedSettings() {
    // Load dark mode setting
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    if (isDarkMode) {
        document.body.classList.add('dark-mode');
        const toggle = document.getElementById('dark-mode-toggle');
        if (toggle) {
            toggle.classList.add('active');
        }
    }
    
    // Load font size setting
    const savedFontSize = localStorage.getItem('fontSize') || 'medium';
    document.body.className = document.body.className.replace(/font-(small|medium|large)/g, '');
    document.body.classList.add(`font-${savedFontSize}`);
    
    const fontSelect = document.getElementById('font-size-select');
    if (fontSelect) {
        fontSelect.value = savedFontSize;
    }
}

// Toggle dark mode
function toggleDarkMode() {
    const toggle = document.getElementById('dark-mode-toggle');
    const body = document.body;
    
    if (body.classList.contains('dark-mode')) {
        body.classList.remove('dark-mode');
        toggle.classList.remove('active');
        localStorage.setItem('darkMode', 'false');
    } else {
        body.classList.add('dark-mode');
        toggle.classList.add('active');
        localStorage.setItem('darkMode', 'true');
    }
}

// Change font size
function changeFontSize() {
    const fontSizeSelect = document.getElementById('font-size-select');
    const selectedSize = fontSizeSelect.value;
    const body = document.body;
    
    // Remove existing font size classes
    body.className = body.className.replace(/font-(small|medium|large)/g, '');
    
    // Add new font size class
    body.classList.add(`font-${selectedSize}`);
    
    // Save to localStorage
    localStorage.setItem('fontSize', selectedSize);
}

// Save settings (for the save button)
function saveSettings() {
    showNotification('Settings saved successfully!', 'success');
}

// Show notification
function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    if (!notification) return;
    
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');
    
    // Hide notification after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

// Mobile menu toggle (for hamburger menu)
function toggleMobileMenu() {
    const navMenu = document.querySelector('.nav-menu');
    const hamburger = document.querySelector('.hamburger');
    
    navMenu.classList.toggle('active');
    hamburger.classList.toggle('active');
}

// Add click event to hamburger menu
document.addEventListener('DOMContentLoaded', function() {
    const hamburger = document.querySelector('.hamburger');
    if (hamburger) {
        hamburger.addEventListener('click', toggleMobileMenu);
    }
});

class SimpleScreenReader {
    constructor() {
        // Load saved settings from localStorage or use defaults
        this.isActive = this.loadSetting('isActive', false);
        this.synth = window.speechSynthesis;
        this.voices = [];
        this.currentVoice = null;
        this.rate = this.loadSetting('rate', 1);
        
        // PDF support
        this.pdfViewers = new Map();
        
        // Flag to prevent auto-reading when modal opens
        this.isModalOpening = false;
        
        this.init();
    }

    // Load a setting from localStorage
    loadSetting(key, defaultValue) {
        try {
            const saved = localStorage.getItem(`screenReader_${key}`);
            if (saved !== null) {
                // Parse boolean and number values
                if (saved === 'true') return true;
                if (saved === 'false') return false;
                const num = parseFloat(saved);
                if (!isNaN(num)) return num;
                return saved;
            }
        } catch (error) {
            console.error('Error loading setting:', key, error);
        }
        return defaultValue;
    }

    // Save a setting to localStorage
    saveSetting(key, value) {
        try {
            localStorage.setItem(`screenReader_${key}`, value);
            console.log(`Saved setting: ${key} = ${value}`);
        } catch (error) {
            console.error('Error saving setting:', key, error);
        }
    }

    init() {
        console.log('Initializing Simple Screen Reader...');
        this.loadVoices();
        this.setupControls();
        this.setupEventListeners();
        this.loadPDFJS();
        
        if (speechSynthesis.onvoiceschanged !== undefined) {
            speechSynthesis.onvoiceschanged = () => this.loadVoices();
        }

        // Apply saved state to UI
        this.updateUIFromSettings();
    }

    updateUIFromSettings() {
        // Update toggle button text
        const toggleBtn = document.getElementById('toggle-reader');
        if (toggleBtn) {
            toggleBtn.textContent = this.isActive ? 'Disable Screen Reader' : 'Enable Screen Reader';
        }

        // Update speed control
        const speedControl = document.getElementById('speed-control');
        if (speedControl) {
            speedControl.value = this.rate;
        }

        // Update voice select (will be set after voices load)
        const savedVoiceIndex = this.loadSetting('voiceIndex', null);
        if (savedVoiceIndex !== null) {
            const voiceSelect = document.getElementById('voice-select');
            if (voiceSelect) {
                voiceSelect.value = savedVoiceIndex;
            }
        }

        console.log('UI updated from saved settings');
    }

    loadPDFJS() {
        if (!window.pdfjsLib) {
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
            script.onload = () => {
                console.log('PDF.js loaded');
                pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
                this.setupPDFWatching();
            };
            script.onerror = () => {
                console.log('PDF.js failed to load, using fallback methods');
                this.setupPDFWatching();
            };
            document.head.appendChild(script);
        } else {
            this.setupPDFWatching();
        }
    }

    setupPDFWatching() {
        console.log('Setting up PDF watching...');
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes') {
                    const target = mutation.target;
                    
                    if (mutation.attributeName === 'src' && 
                        target.classList.contains('pdf-popup')) {
                        console.log('PDF src changed:', target.src);
                        
                        if (target.src && target.src !== 'https://filler-link.co.uk') {
                            const viewer = this.pdfViewers.get(target);
                            
                            // Check if this is a new PDF URL or first time
                            if (viewer) {
                                // Viewer exists, check if URL changed
                                if (viewer.pdfUrl !== target.src) {
                                    console.log('New PDF URL detected, reprocessing...');
                                    // Update the URL and reset the viewer
                                    viewer.pdfUrl = target.src;
                                    viewer.textContent = null;
                                    viewer.isLoaded = false;
                                    
                                    // Close any existing modal
                                    const existingModal = document.querySelector('.pdf-text-modal');
                                    if (existingModal) {
                                        document.body.removeChild(existingModal);
                                    }
                                    
                                    // Process the new PDF
                                    setTimeout(() => {
                                        this.autoDownloadAndProcessPDF(target);
                                    }, 1000);
                                }
                            } else {
                                // First time setup
                                setTimeout(() => {
                                    this.setupPDFIframe(target);
                                }, 1000);
                            }
                        }
                    }
                    
                    if (mutation.attributeName === 'style' && 
                        target.classList.contains('pdf-popup')) {
                        const isVisible = target.style.display !== 'none';
                        console.log('PDF visibility changed:', isVisible);
                        
                        if (isVisible && target.src && target.src !== 'https://filler-link.co.uk') {
                            const viewer = this.pdfViewers.get(target);
                            
                            if (viewer) {
                                // Check if URL changed while becoming visible
                                if (viewer.pdfUrl !== target.src) {
                                    console.log('PDF became visible with new URL, reprocessing...');
                                    viewer.pdfUrl = target.src;
                                    viewer.textContent = null;
                                    viewer.isLoaded = false;
                                    
                                    // Close any existing modal
                                    const existingModal = document.querySelector('.pdf-text-modal');
                                    if (existingModal) {
                                        document.body.removeChild(existingModal);
                                    }
                                    
                                    setTimeout(() => {
                                        this.autoDownloadAndProcessPDF(target);
                                    }, 1000);
                                } else if (!viewer.isLoaded) {
                                    // Same URL but not loaded yet, try loading
                                    console.log('PDF visible but not loaded, processing...');
                                    setTimeout(() => {
                                        this.autoDownloadAndProcessPDF(target);
                                    }, 1000);
                                }
                            } else {
                                // First time setup
                                setTimeout(() => {
                                    this.setupPDFIframe(target);
                                }, 1000);
                            }
                        }
                    }
                }
            });
        });

        observer.observe(document.body, {
            attributes: true,
            subtree: true,
            attributeFilter: ['src', 'style']
        });

        const existingPDF = document.getElementById('default_pdf');
        if (existingPDF) {
            console.log('Found existing PDF iframe');
            this.checkAndSetupPDF(existingPDF);
        }
    }

    checkAndSetupPDF(iframe) {
        if (iframe.style.display !== 'none' && 
            iframe.src && 
            iframe.src !== 'https://filler-link.co.uk' &&
            !this.pdfViewers.has(iframe)) {
            this.setupPDFIframe(iframe);
        }
    }

    setupPDFIframe(iframe) {
        console.log('Setting up PDF iframe:', iframe.id, 'src:', iframe.src);
        
        if (this.pdfViewers.has(iframe)) {
            console.log('PDF already setup');
            return;
        }

        if (iframe.style.display === 'none' || 
            !iframe.src || 
            iframe.src === 'https://filler-link.co.uk') {
            console.log('PDF not ready for setup');
            return;
        }

        if (iframe.parentElement && iframe.parentElement.classList.contains('pdf-wrapper')) {
            console.log('PDF wrapper already exists');
            return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'pdf-wrapper';
        wrapper.setAttribute('tabindex', '0');
        wrapper.setAttribute('role', 'document');
        wrapper.setAttribute('aria-label', 'PDF Document');
        
        wrapper.style.cssText = `
            position: relative;
        `;

        iframe.parentNode.insertBefore(wrapper, iframe);
        wrapper.appendChild(iframe);

        wrapper.addEventListener('focus', () => {
            console.log('PDF wrapper focused');
            this.handlePDFFocus(iframe);
        });

        wrapper.addEventListener('keydown', (e) => {
            console.log('PDF keydown:', e.key);
            this.handlePDFKeydown(e, iframe);
        });

        this.pdfViewers.set(iframe, {
            wrapper: wrapper,
            textContent: null,
            isLoaded: false,
            pdfUrl: iframe.src
        });

        console.log('PDF iframe setup complete');
        
        // Automatically try to download and process the PDF
        this.autoDownloadAndProcessPDF(iframe);
    }

    async autoDownloadAndProcessPDF(iframe) {
        const viewer = this.pdfViewers.get(iframe);
        if (!viewer || !viewer.pdfUrl) return;

        console.log('Auto-downloading PDF for processing:', viewer.pdfUrl);
        
        try {
            // Try direct extraction first (might work for same-origin)
            let textContent = await this.tryDirectExtraction(viewer.pdfUrl);
            
            if (textContent && textContent.length > 0) {
                viewer.textContent = textContent;
                viewer.isLoaded = true;
                console.log('PDF processed successfully via direct extraction');
                
                // Only show modal if screen reader is active
                if (this.isActive) {
                    this.showTextModal(textContent, true);
                }
                return;
            }

            // If direct extraction fails, try downloading as blob
            console.log('Direct extraction failed, trying blob download...');
            textContent = await this.downloadAndProcessPDF(viewer.pdfUrl);
            
            if (textContent && textContent.length > 0) {
                viewer.textContent = textContent;
                viewer.isLoaded = true;
                console.log('PDF processed successfully via blob download');
                
                // Only show modal if screen reader is active
                if (this.isActive) {
                    this.showTextModal(textContent, true);
                }
            } else {
                console.log('Could not process PDF automatically');
            }
        } catch (error) {
            console.error('Auto-download and process failed:', error);
        }
    }

    async tryDirectExtraction(pdfUrl) {
        if (!window.pdfjsLib) return null;

        try {
            console.log('Attempting direct PDF extraction...');
            
            const pdf = await pdfjsLib.getDocument({
                url: pdfUrl,
                cMapUrl: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/cmaps/',
                cMapPacked: true,
                withCredentials: false,
                disableRange: true,
                disableStream: true,
                isEvalSupported: false,
                disableAutoFetch: true,
                disableFontFace: true
            }).promise;
            
            return await this.extractTextFromPDFDocument(pdf);
        } catch (error) {
            console.log('Direct extraction failed:', error.message);
            return null;
        }
    }

    async downloadAndProcessPDF(pdfUrl) {
        if (!window.pdfjsLib) return null;

        try {
            console.log('Downloading PDF as blob...');
            
            // Try to fetch the PDF
            const response = await fetch(pdfUrl, {
                mode: 'cors',
                credentials: 'omit',
                cache: 'no-cache'
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const blob = await response.blob();
            console.log('PDF downloaded as blob, size:', blob.size);

            // Convert blob to array buffer
            const arrayBuffer = await blob.arrayBuffer();
            
            // Process the array buffer
            const pdf = await pdfjsLib.getDocument({
                data: arrayBuffer,
                cMapUrl: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/cmaps/',
                cMapPacked: true
            }).promise;
            
            return await this.extractTextFromPDFDocument(pdf);
        } catch (error) {
            console.error('Blob download and process failed:', error);
            
            // If CORS fails, try using a CORS proxy as last resort
            return await this.tryWithCORSProxy(pdfUrl);
        }
    }

    async tryWithCORSProxy(pdfUrl) {
        if (!window.pdfjsLib) return null;

        try {
            console.log('Trying with CORS proxy...');
            
            // Use a CORS proxy (you can change this to a different proxy if needed)
            const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(pdfUrl)}`;
            
            const response = await fetch(proxyUrl);
            
            if (!response.ok) {
                throw new Error(`Proxy HTTP ${response.status}`);
            }

            const arrayBuffer = await response.arrayBuffer();
            
            const pdf = await pdfjsLib.getDocument({
                data: arrayBuffer,
                cMapUrl: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/cmaps/',
                cMapPacked: true
            }).promise;
            
            console.log('PDF processed via CORS proxy');
            return await this.extractTextFromPDFDocument(pdf);
        } catch (error) {
            console.error('CORS proxy method failed:', error);
            return null;
        }
    }

    async extractTextFromPDFDocument(pdf) {
        console.log(`Extracting text from PDF: ${pdf.numPages} pages`);
        
        const textContent = [];
        const maxPages = Math.min(pdf.numPages, 50);
        
        for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
            try {
                console.log(`Extracting page ${pageNum}...`);
                const page = await pdf.getPage(pageNum);
                const content = await page.getTextContent();
                
                const pageText = content.items
                    .map(item => item.str)
                    .join(' ')
                    .replace(/\s+/g, ' ')
                    .trim();
                
                if (pageText) {
                    textContent.push({
                        pageNumber: pageNum,
                        text: pageText
                    });
                    console.log(`Page ${pageNum} extracted: ${pageText.length} characters`);
                }
            } catch (pageError) {
                console.error(`Error extracting page ${pageNum}:`, pageError);
            }
        }
        
        if (pdf.numPages > maxPages) {
            console.log(`Note: Only extracted first ${maxPages} of ${pdf.numPages} pages`);
        }
        
        return textContent;
    }

    handlePDFFocus(iframe) {
        if (!this.isActive) return;
        
        const viewer = this.pdfViewers.get(iframe);
        
        if (viewer && viewer.isLoaded && viewer.textContent) {
            this.speak(`PDF document loaded with ${viewer.textContent.length} pages. Press R to read content, E to extract text, D to describe PDF, or F to focus PDF.`);
        } else if (viewer && viewer.pdfUrl && viewer.pdfUrl !== 'https://filler-link.co.uk') {
            this.speak('PDF document is loading. Please wait. Press R to read content, E to extract text, D to describe PDF, or F to focus PDF.');
        } else {
            this.speak('PDF viewer - no document loaded.');
        }
    }

    handlePDFKeydown(event, iframe) {
        if (!this.isActive) return;

        switch(event.key.toLowerCase()) {
            case 'r':
                event.preventDefault();
                this.readPDF(iframe);
                break;
            case 'e':
                event.preventDefault();
                this.extractAndShowPDFText(iframe);
                break;
            case 'd':
                event.preventDefault();
                this.describePDF(iframe);
                break;
            case 'f':
                event.preventDefault();
                iframe.focus();
                this.speak('PDF focused');
                break;
            case 'l':
                event.preventDefault();
                this.reloadPDF(iframe);
                break;
        }
    }

    async reloadPDF(iframe) {
        const viewer = this.pdfViewers.get(iframe);
        if (!viewer || !viewer.pdfUrl) {
            this.speak('No PDF to reload');
            return;
        }

        this.speak('Reloading PDF...');
        viewer.textContent = null;
        viewer.isLoaded = false;
        
        await this.autoDownloadAndProcessPDF(iframe);
    }

    async describePDF(iframe) {
        console.log('Describing PDF...');
        
        const viewer = this.pdfViewers.get(iframe);
        
        if (!viewer || !viewer.pdfUrl || viewer.pdfUrl === 'https://filler-link.co.uk') {
            this.speak('No PDF loaded to describe');
            return;
        }

        try {
            let description = 'PDF document. ';
            
            if (viewer.isLoaded && viewer.textContent) {
                const pageCount = viewer.textContent.length;
                const totalChars = viewer.textContent.reduce((sum, page) => sum + page.text.length, 0);
                description += `Successfully loaded with ${pageCount} pages and approximately ${totalChars} characters of text. `;
                
                const firstPage = viewer.textContent[0];
                if (firstPage && firstPage.text) {
                    const preview = firstPage.text.substring(0, 200).trim();
                    description += `Preview: ${preview}...`;
                }
            } else {
                description += 'Loading in progress. Text content not yet available. Try again in a moment or press L to reload.';
            }

            this.speak(description);
        } catch (error) {
            console.error('PDF description failed:', error);
            this.speak('Failed to describe PDF');
        }
    }

    async readPDF(iframe) {
        console.log('Reading PDF...');
        
        const viewer = this.pdfViewers.get(iframe);
        
        if (!viewer) {
            this.speak('No PDF viewer found');
            return;
        }

        if (viewer.isLoaded && viewer.textContent && viewer.textContent.length > 0) {
            console.log('Using loaded PDF text');
            this.speakPDFContent(viewer.textContent);
            return;
        }

        if (!viewer.pdfUrl || viewer.pdfUrl === 'https://filler-link.co.uk') {
            this.speak('No PDF loaded to read');
            return;
        }

        // If not loaded yet, try to load it now
        this.speak('PDF is still loading. Attempting to read now...');
        
        try {
            await this.autoDownloadAndProcessPDF(iframe);
            
            // Check again after loading attempt
            if (viewer.textContent && viewer.textContent.length > 0) {
                this.speakPDFContent(viewer.textContent);
            } else {
                this.speak('Could not extract text from PDF. The PDF may be image-based, protected, or there may be access restrictions. Press L to try reloading.');
            }
        } catch (error) {
            console.error('PDF reading failed:', error);
            this.speak('Failed to read PDF content. Press L to try reloading.');
        }
    }

    speakPDFContent(textContent) {
        if (!textContent || textContent.length === 0) {
            this.speak('No text content found in PDF');
            return;
        }

        let fullText = `PDF document with ${textContent.length} pages. `;
        
        const pagesToRead = Math.min(textContent.length, 3);
        
        for (let i = 0; i < pagesToRead; i++) {
            const pageData = textContent[i];
            if (pageData.text) {
                const pageText = pageData.text.length > 1000 ? 
                    pageData.text.substring(0, 1000) + '... content truncated' : 
                    pageData.text;
                fullText += `Page ${pageData.pageNumber}: ${pageText}. `;
            }
        }

        if (textContent.length > pagesToRead) {
            fullText += `And ${textContent.length - pagesToRead} more pages. Use extract text to see all content.`;
        }

        this.speak(fullText);
    }

    async extractAndShowPDFText(iframe) {
        console.log('Extracting and showing PDF text...');
        
        const viewer = this.pdfViewers.get(iframe);
        
        if (!viewer) {
            this.speak('No PDF viewer found');
            return;
        }

        if (viewer.isLoaded && viewer.textContent) {
            this.showTextModal(viewer.textContent, false);
            this.speak('Text displayed');
            return;
        }
        
        if (!viewer.pdfUrl || viewer.pdfUrl === 'https://filler-link.co.uk') {
            this.speak('No PDF loaded to extract text from');
            return;
        }

        try {
            this.speak('Extracting text...');
            
            await this.autoDownloadAndProcessPDF(iframe);
            
            if (viewer.textContent && viewer.textContent.length > 0) {
                this.showTextModal(viewer.textContent, false);
                this.speak('Text extracted and displayed');
            } else {
                this.speak('No text could be extracted from this PDF. Press L to try reloading.');
            }
        } catch (error) {
            console.error('Text extraction failed:', error);
            this.speak('Text extraction failed. Press L to try reloading.');
        }
    }

    showTextModal(textContent, isAutomatic = false) {
        // Check if modal already exists
        const existingModal = document.querySelector('.pdf-text-modal');
        if (existingModal) {
            console.log('Modal already open, not opening another');
            return;
        }

        // Set flag to prevent auto-reading
        this.isModalOpening = true;

        let fullText = '';
        textContent.forEach(pageData => {
            fullText += `Page ${pageData.pageNumber}:\n${pageData.text}\n\n`;
        });

        const modal = document.createElement('div');
        modal.className = 'pdf-text-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        `;
        
        const autoLabel = isAutomatic ? ' (Auto-opened)' : '';
        
        modal.innerHTML = `
            <div style="background: white; border-radius: 8px; width: 90%; max-width: 800px; max-height: 90%; display: flex; flex-direction: column;">
                <div style="padding: 15px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0;">Extracted PDF Text (${textContent.length} pages)${autoLabel}</h2>
                    <button class="close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer;" aria-label="Close">×</button>
                </div>
                <div style="padding: 15px; flex: 1; overflow: hidden;">
                    <textarea readonly="" style="width: 100%; height: 400px; border: 1px solid #ddd; padding: 10px; font-family: monospace; font-size: 12px; resize: none;" aria-label="PDF extracted text">${fullText}</textarea>
                </div>
                <div style="padding: 15px; border-top: 1px solid #ddd; text-align: right;">
                    <button class="read-btn" style="padding: 8px 16px; background: #007acc; color: white; border: none; border-radius: 4px; margin-right: 10px; cursor: pointer;">Read Aloud</button>
                    <button class="copy-btn" style="padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; margin-right: 10px; cursor: pointer;">Copy</button>
                    <button class="close-btn" style="padding: 8px 16px; background: #ccc; border: none; border-radius: 4px; cursor: pointer;">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close modal function
        const closeModal = () => {
            if (document.body.contains(modal)) {
                document.body.removeChild(modal);
            }
        };

        // Close button handlers
        modal.querySelectorAll('.close-btn').forEach(btn => {
            btn.addEventListener('click', closeModal);
        });

        // Close on escape key
        const escapeHandler = (e) => {
            if (e.key === 'Escape') {
                closeModal();
                document.removeEventListener('keydown', escapeHandler);
            }
        };
        document.addEventListener('keydown', escapeHandler);

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal();
            }
        });

        // Copy text
        modal.querySelector('.copy-btn').addEventListener('click', () => {
            navigator.clipboard.writeText(fullText).then(() => {
                this.speak('Text copied to clipboard');
            }).catch(err => {
                console.error('Copy failed:', err);
                this.speak('Failed to copy text');
            });
        });

        // Read text aloud
        modal.querySelector('.read-btn').addEventListener('click', () => {
            this.speak(fullText);
        });

        // Focus textarea without selecting text
        const textarea = modal.querySelector('textarea');
        setTimeout(() => {
            textarea.focus();
            // Move cursor to start instead of selecting
            textarea.setSelectionRange(0, 0);
            
            // Reset the flag after a short delay to allow normal selection reading
            setTimeout(() => {
                this.isModalOpening = false;
            }, 500);
        }, 100);

        console.log('Text modal displayed', isAutomatic ? '(automatically)' : '(manually)');
    }

    setupEventListeners() {
        document.addEventListener('mouseup', () => this.handleTextSelection());
        document.addEventListener('focusin', (e) => this.handleFocus(e));
        
        document.addEventListener('keydown', (e) => {
            if (!this.isActive) return;
            
            if (e.ctrlKey && e.shiftKey && e.key === 'S') {
                e.preventDefault();
                this.toggle();
            }
        });
    }

    handleTextSelection() {
        if (!this.isActive) return;
        
        // Don't read text if modal is currently opening
        if (this.isModalOpening) {
            console.log('Modal opening, skipping text selection reading');
            return;
        }
        
        const selection = window.getSelection();
        const selectedText = selection.toString().trim();
        
        if (selectedText) {
            this.speak(selectedText);
        }
    }

    handleFocus(event) {
        if (!this.isActive) return;
        
        const element = event.target;
        
        if (element.classList.contains('pdf-wrapper')) {
            return;
        }
        
        const text = this.getElementText(element);
        if (text) {
            const type = this.getElementType(element);
            this.speak(`${type}: ${text}`);
        }
    }

    getElementText(element) {
        if (!element) return '';
        
        if (element.tagName === 'BUTTON') {
            return element.textContent || 'button';
        } else if (element.tagName === 'INPUT') {
            return element.value || element.placeholder || 'input';
        } else if (element.tagName === 'A') {
            return element.textContent || 'link';
        } else {
            return element.textContent || element.getAttribute('aria-label') || '';
        }
    }

    getElementType(element) {
        const tag = element.tagName.toLowerCase();
        
        switch(tag) {
            case 'button': return 'Button';
            case 'input': return 'Input';
            case 'a': return 'Link';
            case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6':
                return `Heading level ${tag.charAt(1)}`;
            default: return 'Element';
        }
    }

    loadVoices() {
        this.voices = this.synth.getVoices();
        this.populateVoiceSelect();
        
        // Try to load saved voice
        const savedVoiceIndex = this.loadSetting('voiceIndex', null);
        if (savedVoiceIndex !== null && this.voices[savedVoiceIndex]) {
            this.currentVoice = this.voices[savedVoiceIndex];
            console.log('Loaded saved voice:', this.currentVoice.name);
        } else {
            // Default to English voice
            const englishVoice = this.voices.find(voice => 
                voice.lang.startsWith('en')
            );
            this.currentVoice = englishVoice || this.voices[0];
        }
    }

    populateVoiceSelect() {
        const voiceSelect = document.getElementById('voice-select');
        if (!voiceSelect) return;
        
        voiceSelect.innerHTML = '';
        this.voices.forEach((voice, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = `${voice.name} (${voice.lang})`;
            voiceSelect.appendChild(option);
        });

        // Set saved voice in dropdown
        const savedVoiceIndex = this.loadSetting('voiceIndex', null);
        if (savedVoiceIndex !== null) {
            voiceSelect.value = savedVoiceIndex;
        }
    }

    setupControls() {
        const toggleBtn = document.getElementById('toggle-reader');
        const speedControl = document.getElementById('speed-control');
        const voiceSelect = document.getElementById('voice-select');

        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggle());
        }
        
        if (speedControl) {
            speedControl.addEventListener('input', (e) => {
                this.rate = parseFloat(e.target.value);
                this.saveSetting('rate', this.rate);
            });
        }

        if (voiceSelect) {
            voiceSelect.addEventListener('change', (e) => {
                const voiceIndex = parseInt(e.target.value);
                this.currentVoice = this.voices[voiceIndex];
                this.saveSetting('voiceIndex', voiceIndex);
                console.log('Voice changed and saved:', this.currentVoice.name);
            });
        }
    }

    speak(text) {
        if (!text) return;
        
        console.log('Speaking:', text.substring(0, 100) + '...');
        this.synth.cancel();
        
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.voice = this.currentVoice;
        utterance.rate = this.rate;
        
        this.synth.speak(utterance);
    }

    toggle() {
        this.isActive = !this.isActive;
        this.saveSetting('isActive', this.isActive);
        
        const toggleBtn = document.getElementById('toggle-reader');
        
        if (this.isActive) {
            if (toggleBtn) toggleBtn.textContent = 'Disable Screen Reader';
            this.speak('Screen reader activated');
            console.log('Screen reader activated');
        } else {
            if (toggleBtn) toggleBtn.textContent = 'Enable Screen Reader';
            this.synth.cancel();
            console.log('Screen reader deactivated');
        }
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing screen reader...');
    window.screenReader = new SimpleScreenReader();
});

