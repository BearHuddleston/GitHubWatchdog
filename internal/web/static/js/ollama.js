/**
 * Ollama integration for GitHub Watchdog
 * This script handles the generation and display of AI-powered security analyses
 */

class OllamaAnalysis {
  constructor() {
    this.currentEntityType = null;
    this.currentEntityId = null;
  }

  // Generate analysis for a repository or user
  async generateAnalysis(entityType, entityId) {
    this.currentEntityType = entityType;
    this.currentEntityId = entityId;
    
    // Get UI elements
    const button = document.getElementById('generateAnalysisBtn');
    const ollamaSection = document.getElementById('ollamaAnalysisSection');
    
    if (!button || !ollamaSection) return;
    
    // Update button state
    const buttonText = button.querySelector('.button-text');
    const loader = button.querySelector('.analysis-loading');
    buttonText.textContent = 'Generating analysis...';
    loader.style.display = 'inline-block';
    button.disabled = true;
    
    try {
      // Make API request to generate analysis
      const response = await fetch('/api/analysis/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          entity_type: entityType,
          entity_id: entityId
        })
      });
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Display the analysis with markdown rendering
      ollamaSection.style.display = 'block';
      const analysisContent = document.getElementById('ollamaAnalysisContent');
      
      if (analysisContent && data.analysis) {
        analysisContent.innerHTML = markdownRenderer.render(data.analysis);
      } else {
        throw new Error('No analysis returned from the server');
      }
    } catch (error) {
      console.error('Error generating analysis:', error);
      ollamaSection.style.display = 'block';
      const analysisContent = document.getElementById('ollamaAnalysisContent');
      
      if (analysisContent) {
        analysisContent.innerHTML = `<div class="error">Failed to generate analysis: ${error.message}</div>`;
      }
    } finally {
      // Reset button state
      buttonText.textContent = 'Generate AI Analysis';
      loader.style.display = 'none';
      button.disabled = false;
    }
  }

  // Initialize analysis button in the report modal
  initializeAnalysisButton() {
    // Check if there's existing analysis in the report data
    const existingAnalysis = document.getElementById('existingOllamaAnalysis');
    if (existingAnalysis && existingAnalysis.textContent.trim()) {
      // Show the existing analysis section
      const ollamaSection = document.getElementById('ollamaAnalysisSection');
      if (ollamaSection) {
        ollamaSection.style.display = 'block';
      }
      
      // Format the existing analysis with markdown
      const analysisContent = document.getElementById('ollamaAnalysisContent');
      if (analysisContent) {
        analysisContent.innerHTML = markdownRenderer.render(existingAnalysis.textContent);
      }
      return;
    }
    
    // Set up the analysis button
    const button = document.getElementById('generateAnalysisBtn');
    if (button) {
      button.addEventListener('click', () => {
        if (this.currentEntityType && this.currentEntityId) {
          this.generateAnalysis(this.currentEntityType, this.currentEntityId);
        }
      });
    }
  }
}

// Create a global instance
const ollamaAnalysis = new OllamaAnalysis();