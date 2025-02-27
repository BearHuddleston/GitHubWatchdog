/**
 * Simple Markdown parser and renderer for the report modal
 * This is a lightweight alternative to larger libraries like marked.js
 */
class MarkdownRenderer {
  constructor() {
    this.rules = [
      // Headers
      { pattern: /^# (.+)$/gm, replacement: '<h1>$1</h1>' },
      { pattern: /^## (.+)$/gm, replacement: '<h2>$1</h2>' },
      { pattern: /^### (.+)$/gm, replacement: '<h3>$1</h3>' },
      { pattern: /^#### (.+)$/gm, replacement: '<h4>$1</h4>' },
      { pattern: /^##### (.+)$/gm, replacement: '<h5>$1</h5>' },
      { pattern: /^###### (.+)$/gm, replacement: '<h6>$1</h6>' },
      
      // Bold and italic
      { pattern: /\*\*(.+?)\*\*/g, replacement: '<strong>$1</strong>' },
      { pattern: /\*(.+?)\*/g, replacement: '<em>$1</em>' },
      { pattern: /__(.+?)__/g, replacement: '<strong>$1</strong>' },
      { pattern: /_(.+?)_/g, replacement: '<em>$1</em>' },
      
      // Code blocks
      { pattern: /```([^`]+)```/gs, replacement: '<pre><code>$1</code></pre>' },
      { pattern: /`([^`]+)`/g, replacement: '<code>$1</code>' },
      
      // Lists
      { pattern: /^\s*[\-\*]\s+(.+)$/gm, replacement: '<li>$1</li>' },
      { pattern: /^\s*\d+\.\s+(.+)$/gm, replacement: '<li>$1</li>' },
      
      // Blockquotes
      { pattern: /^>\s(.+)$/gm, replacement: '<blockquote>$1</blockquote>' },
      
      // Links
      { pattern: /\[([^\]]+)\]\(([^)]+)\)/g, replacement: '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>' },
      
      // Images
      { pattern: /!\[([^\]]+)\]\(([^)]+)\)/g, replacement: '<img src="$2" alt="$1">' },
      
      // Horizontal rules
      { pattern: /^\s*[\-\*\_]{3,}\s*$/gm, replacement: '<hr>' },
      
      // Handle paragraphs and line breaks
      { pattern: /\n\n/g, replacement: '</p><p>' }
    ];
  }

  // Process lists to add <ul> or <ol> tags
  processLists(html) {
    // Process unordered lists
    html = html.replace(/<li>(.+?)<\/li>/g, function(match) {
      if (!match.startsWith('<ul>')) {
        return '<ul>' + match + '</ul>';
      }
      return match;
    });
    
    // Join adjacent list items
    html = html.replace(/<\/ul>\s*<ul>/g, '');
    
    return html;
  }
  
  // Process blockquotes to combine adjacent ones
  processBlockquotes(html) {
    // Join adjacent blockquotes
    html = html.replace(/<\/blockquote>\s*<blockquote>/g, '<br>');
    
    return html;
  }

  render(markdown) {
    if (!markdown) return '';
    
    // Escape HTML characters
    let html = markdown
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
      
    // Add paragraph tags
    html = '<p>' + html + '</p>';
    
    // Apply markdown rules
    this.rules.forEach(rule => {
      html = html.replace(rule.pattern, rule.replacement);
    });
    
    // Process lists and blockquotes
    html = this.processLists(html);
    html = this.processBlockquotes(html);
    
    return html;
  }
}

// Create a global instance
const markdownRenderer = new MarkdownRenderer();