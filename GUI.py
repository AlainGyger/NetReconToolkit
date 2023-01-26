import curses
import Scratch
import time

def main(stdscr):
    # Clear screen
    stdscr.clear()

    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)

    # Draw a border around the screen
    stdscr.border()

    # Print a message in the center of the screen
    height, width = stdscr.getmaxyx()
    message = "Welcome to ncurses!"
    x = width//2 - len(message)//2
    y = height//2
    stdscr.addstr(y, x, message, curses.color_pair(1))

    # Create IP input field
    x = width//2 - 15
    y = y + 2
    stdscr.addstr(y, x, "IP: ", curses.color_pair(2))
    curses.echo()
    ip = stdscr.getstr(y, x + 4, 15).decode("utf-8")

    # Print the entered IP address
    stdscr.addstr(y + 2, x, "Scanning IP: " + ip)
    stdscr.refresh()

    # Wait for user input
    # stdscr.getch()

    scan_result = Scratch.single_ip_scan(ip)

    stdscr.clear()

    # Add a row of 10 addressable boxes
    y = height
    x = width
    box_list = []
    for i in range(15):
        box = stdscr.subwin(3, 5, y, x + i * 6)
        box.box()
        box_list.append(box)
        stdscr.refresh()

    # Print the dictionary
    y = y
    x = width//2 - 15
    stdscr.addstr(y, x, "Scan Results: ", curses.color_pair(2))
    for i, (key, value) in enumerate(scan_result.items()):
        stdscr.addstr(y+i+1, x, f"{key}: {value}")
    stdscr.refresh()
    # Wait for user input
    stdscr.getch()

    stdscr.clear()


    stdscr.refresh()

    # Wait for user input
    stdscr.getch()

curses.wrapper(main)
