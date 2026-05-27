# AICU Demo Recording
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs demo.tape

Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

# Title
Type "# AICU - LLM Security Scanner Demo"
Enter
Sleep 1s

# Start the vulnerable demo server in background
Type "python demo_server.py &"
Enter
Sleep 2s

# Show the example request
Type "cat examples/demo_request.txt"
Enter
Sleep 2s

# Run the scan
Type "aicu scan --request examples/demo_request.txt"
Enter
Sleep 8s

# Show results
Type "echo '---'"
Enter
Type "echo 'Scan complete. Check runs/ for full report.'"
Enter
Sleep 2s

# Kill the demo server
Type "kill %1 2>/dev/null"
Enter
Sleep 1s
