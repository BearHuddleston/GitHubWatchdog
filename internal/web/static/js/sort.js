document.addEventListener('DOMContentLoaded', function() {
    // Find all sortable table headers
    const sortableHeaders = document.querySelectorAll('th.sortable');
    
    // Add click event listeners to all sortable headers
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const columnName = this.dataset.column;
            let newOrder;
            
            // Toggle sort direction or default to 'asc'
            if (this.classList.contains('asc')) {
                newOrder = 'desc';
            } else if (this.classList.contains('desc')) {
                newOrder = 'asc';
            } else {
                newOrder = 'asc';
            }
            
            // Get current URL and update or add sort parameters
            const url = new URL(window.location.href);
            url.searchParams.set('sort', columnName);
            url.searchParams.set('order', newOrder);
            
            // Maintain pagination parameters
            const page = url.searchParams.get('page');
            if (page) {
                url.searchParams.set('page', page);
            }
            
            const limit = url.searchParams.get('limit');
            if (limit) {
                url.searchParams.set('limit', limit);
            }
            
            // Navigate to the new URL
            window.location.href = url.toString();
        });
    });
    
    // Highlight current sort column and direction
    const currentSortColumn = document.querySelector(`th.sortable[data-column="${currentSort}"]`);
    if (currentSortColumn) {
        // Remove any existing sort classes
        sortableHeaders.forEach(header => {
            header.classList.remove('asc', 'desc');
        });
        
        // Add the appropriate sort class
        currentSortColumn.classList.add(currentSortOrder.toLowerCase());
    }
});