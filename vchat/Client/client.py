#!/usr/bin/python3

####################
# based on https://www.geeksforgeeks.org/gui-chat-application-using-tkinter-in-python/

# run a python script in terminal without the python command
# Use a shebang line at the "start" of your script:
# #!/usr/bin/python3

# make the file executable:
# chmod +x arbitraryname

# if necessary, put it in a directory on your PATH (can be a symlink):
# cd ~/bin/
##################################

# import all the required modules
import socket
import threading
from tkinter import *
from tkinter import messagebox
import os
import re

# import all functions /
# everthing from chat.py file?
# from chat import *

#  Default values for the Port and Server that are in the input fields.
PORT = 9999
SERVER = "10.0.2.7"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

# Regular expression used to validate the IPv4 address user entered is valid
IPV4_REGEX = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

# Create a new client socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# GUI class for the chat


class GUI:

    """ Constructor Method
    The constructor method initializes and hides the chat window.
    Subsequently, it initializes and generates the user interface elements for
    the login window. Additionally, generates protocols to handle the
    window being closed.
    """

    def __init__(self):

        # chat window which is currently hidden
        self.Window = Tk()
        self.Window.withdraw()
        # Position the window
        self.Window.geometry("+100+50")

        # login window
        self.login = Toplevel()
        # set the title
        self.login.title("Login")
        self.login.resizable(width=True, height=True)
        self.login.configure(width=400, height=300)

        # Position the login window
        self.login.geometry("+50+25")

        # create a Label
        self.pls = Label(self.login,
                         text="Please login to continue",
                         justify=CENTER,
                         font="Helvetica 14 bold")
        self.pls.place(relheight=0.15,
                       relx=0.1,
                       rely=0.02)
        # create a Label
        self.labelName = Label(self.login,
                               text="Your Name: ",
                               font="Helvetica 12")
        self.labelName.place(relheight=0.2,
                             relx=0.1,
                             rely=0.2)
        # create a entry box for typing the message
        self.entryName = Entry(self.login, font="Helvetica 14")
        self.entryName.place(relwidth=0.4,
                             relheight=0.12,
                             relx=0.35,
                             rely=0.2)
        # set the focus of the curser
        self.entryName.focus()

        # create a IP label
        self.labelIP = Label(self.login,
                             text="IP: ",
                             font="Helvetica 12")
        self.labelIP.place(relheight=0.2,
                           relx=0.1,
                           rely=0.35)
        # create a entry box for typing IP
        self.entryIP = Entry(self.login, font="Helvetica 14")
        self.entryIP.place(relwidth=0.4,
                           relheight=0.12,
                           relx=0.35,
                           rely=0.35)
        self.entryIP.insert(END, SERVER)

        # create a port label
        self.labelPort = Label(self.login,
                               text="Port: ",
                               font="Helvetica 12")
        self.labelPort.place(relheight=0.2,
                             relx=0.1,
                             rely=0.5)
        # create a entry box for typing port
        self.entryPort = Entry(self.login, font="Helvetica 14")
        self.entryPort.place(relwidth=0.4,
                             relheight=0.12,
                             relx=0.35,
                             rely=0.5)
        self.entryPort.insert(END, str(PORT))

        # create a Continue Button along with action
        self.go = Button(self.login,
                         text="CONTINUE",
                         font="Helvetica 14 bold",
                         command=lambda: self.go_ahead(self.entryName.get()))
        self.go.place(relx=0.6,
                      rely=0.85)

        self.Window.protocol("WM_DELETE_WINDOW", self.on_close_window)
        self.login.protocol("WM_DELETE_WINDOW", self.on_close_login)
        self.Window.mainloop()

    """
    Handles when the login view is closed.
    Destroys the view window, closes the client, and exits the program
    """

    def on_close_login(self):
        #                if messagebox.askokcancel("Quit", "Do you want to quit?"):
        self.login.destroy()
        # message="EXIT"
        # client.send(message.encode(FORMAT))
        try:
            client.close()
        except OSError:
            os._exit(1)

        # exit(0) # this exit will hang over there because of the receiving thread
        os._exit(0)  # this exit will exit everything including threads;

    """
    Handles when the chat view is closed.
    Sends an exit message, closes the client, and then exits the program
    """

    def on_close_window(self):
     #               if messagebox.askokcancel("Quit", "Do you want to quit?"):
        self.Window.destroy()
        message = "EXIT"
        try:
            client.send(message.encode(FORMAT))
            client.close()
            os._exit(1)
        except OSError:
            os._exit(1)

    """ Uses a regular expression to validate the IPv4 address is correct """

    def valid_ip_addr(self, ip):
        return re.search(IPV4_REGEX, ip)

    """ Validates that the port entered is an unsigned 16-bit value """

    def valid_port(self, port):
        # first validate that port is able to be cast to an integer
        try:
            int(port)
        except ValueError:
            return False

        return 1 <= int(port) <= 65535

    """
    Called when the login button is pressed.
    Validates that all information is correct and starts a thread to recieve
    messages after the client is connected
    """

    def go_ahead(self, name):
        SERVER = self.entryIP.get()

        # Verify that all fields are at a minimum present
        if (len(SERVER) > 0
                and len(self.entryPort.get()) > 0
                and len(self.entryName.get()) > 0):
            if self.valid_ip_addr(SERVER):
                if self.valid_port(self.entryPort.get()):
                    # port guaranteed to be able to cast to int without error
                    PORT = int(self.entryPort.get())
                    ADDRESS = (SERVER, PORT)

                    # if port and IPv4 address are valid try to connect
                    # the client
                    try:
                        client.connect(ADDRESS)
                    except OSError as e:
                        # print("Caught exception socket.error : %s" % e)
                        messagebox.showinfo(
                            "GenCyber ChatRoom",
                            str(e))
                        return

                    # If the client is able to connect, change displayed window
                    self.login.destroy()
                    self.layout(name)

                    # the thread to receive messages
                    rcv = threading.Thread(target=self.receive)
                    rcv.start()
                else:
                    messagebox.showinfo(
                        "GenCyber ChatRoom",
                        "The port entered is invalid")
            else:
                messagebox.showinfo(
                    "GenCyber ChatRoom",
                    "The IP Address entered is invalid")
        else:
            messagebox.showinfo(
                "GenCyber Chatroom",
                "Not all of the required fields are complete")

    # The main layout of the chat

    """
    Layout the chat window and make that the focused view.
    """

    def layout(self, name):

        self.name = name
        # to show chat window
        self.Window.deiconify()
        self.Window.title("GenCyber Chat Room")
        self.Window.resizable(width=True,
                              height=True)
        self.Window.configure(width=470,
                              height=350,
                              bg="#17202A")

        # Add client's name to the header of the window
        self.labelHead = Label(self.Window,
                               bg="#EAECEE",
                               fg="#17202A",
                               text=self.name,
                               font="Helvetica 12 bold",
                               pady=5)

        self.labelHead.place(relwidth=1)

        # draw separator between header and the chat view
        self.line = Label(self.Window,
                          width=450,
                          bg="#ABB2B9")

        self.line.place(relwidth=1,
                        rely=0.07,
                        relheight=0.012)

        # draw chat view
        self.textCons = Text(self.Window,
                             width=20,
                             height=2,
                             bg="#EAECEE",
                             fg="#17202A",
                             font="Helvetica 12",
                             padx=5,
                             pady=5)

        self.textCons.place(relheight=0.745,
                            relwidth=1,
                            rely=0.08)

        # add right click menu functionality to the chat window
        self.the_menu = Menu(self.textCons, tearoff=0)
        self.the_menu.add_command(label="Cut")
        self.the_menu.add_command(label="Copy")
        self.the_menu.add_command(label="Paste")

        # Enable copy and paste of text in the Text class
        self.textCons.bind_class(
            "Text", "<Button-3><ButtonRelease-3>", self.show_menu)

        # create a background view for the text field and send button
        self.labelBottom = Label(self.Window,
                                 bg="#ABB2B9",
                                 height=80)

        self.labelBottom.place(relwidth=1,
                               rely=0.825)

        # text field for entering text to send
        self.entryMsg = Entry(self.labelBottom,
                              bg="#EAECEE",
                              fg="#2C3E50",
                              font="Helvetica 12")

        # place the given widget
        # into the gui window
        self.entryMsg.place(relwidth=0.74,
                            relheight=0.03,
                            rely=0.008,
                            relx=0.011)

        self.entryMsg.focus()

        # add an event callback when the Return key is pressed
        self.entryMsg.bind('<Return>', self.return_key_callback)

        # create a Send Button
        self.buttonMsg = Button(self.labelBottom,
                                text="Send",
                                font="Helvetica 10 bold",
                                width=20,
                                bg="#ABB2B9",
                                command=lambda: self.send_button(self.entryMsg.get()))

        self.buttonMsg.place(relx=0.77,
                             rely=0.008,
                             relheight=0.03,
                             relwidth=0.22)

        self.textCons.config(cursor="arrow")

        # create a scroll bar
        scrollbar = Scrollbar(self.textCons)

        # place the scroll bar
        # into the gui window
        scrollbar.place(relheight=1, relx=0.974)

        scrollbar.config(command=self.textCons.yview)

        self.textCons.config(state=DISABLED)

    """
    Event callback for when the Return key is pressed while the message Entry
    widget is focused
    """
    def return_key_callback(self, _):
        self.send_button(self.entryMsg.get())

    """
    When the user right-clicks on the window, show_menu displays a
    window with options to the user.
    """

    def show_menu(self, e):
        w = e.widget
        self.the_menu.entryconfigure(
            "Cut", command=lambda: w.event_generate("<<Cut>>"))
        self.the_menu.entryconfigure(
            "Copy", command=lambda: w.event_generate("<<Copy>>"))
        self.the_menu.entryconfigure(
            "Paste", command=lambda: w.event_generate("<<Paste>>"))
        self.the_menu.tk.call("tk_popup", self.the_menu, e.x_root, e.y_root)

    """
    Basically start the thread for sending messages
    """

    def send_button(self, msg):
        self.textCons.config(state=DISABLED)
        self.msg = msg
        self.entryMsg.delete(0, END)
        snd = threading.Thread(target=self.send_message)
        snd.start()

    """
    Function to receive messages
    """

    def receive(self):
        while True:
            try:
                message = client.recv(1024).decode(FORMAT)

                # if the messages from the server is NAME send the
                # client's name
                if message == 'NAME':
                    client.send(self.name.encode(FORMAT))
                else:
                    # insert messages to text box
                    self.textCons.config(state=NORMAL)
                    self.textCons.insert(END, message+"\n")

                    self.textCons.config(state=DISABLED)
                    self.textCons.see(END)
            except OSError as e:
                messagebox.showinfo("GenCyber ChatRoom", str(e))
                # an error will be printed on the command line or console if
                # there's an error
                print("An error occured!")
                client.close()
                break

    """
    Function to send messages
    """

    def send_message(self):
        self.textCons.config(state=DISABLED)
        while True:
            message = (f"<Me>: {self.msg}")

            # insert messages to text box
            self.textCons.config(state=NORMAL)
            self.textCons.insert(END, message+"\n")

            self.textCons.config(state=DISABLED)
            self.textCons.see(END)

            message = (f"KNOCK {self.name}: {self.msg}")

            try:
                client.send(message.encode(FORMAT))
            except OSError as e:
                messagebox.showinfo("GenCyber ChatRoom", str(e))
                break

            break


# create a GUI class object
g = GUI()
