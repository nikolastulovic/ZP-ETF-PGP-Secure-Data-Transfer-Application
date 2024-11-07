import _sha1
import base64
import glob
import os
import secrets
import sys
import time

from Crypto.PublicKey import RSA
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QComboBox, QPushButton, QVBoxLayout, QWidget, \
    QStackedWidget, QAction, QHBoxLayout, QTextEdit, QSpinBox, QCheckBox, QDialog, QRadioButton, QTableWidgetItem, \
    QHeaderView, QTableWidget, QFileDialog, QMessageBox, QInputDialog, QButtonGroup, QScrollArea

import rings
from algorithms import zipAlg, aes128, tripleDES
from algorithms import radix64 as radix


class PGPWindow(QMainWindow):
    current_user = None
    public_keys_loaded = False

    def __init__(self):
        super().__init__()
        self.show_menu = False
        self.initUI()

    def initUI(self):
        self.setWindowTitle('PGP')
        self.setGeometry(100, 100, 1150, 600)

        # Apply stylesheet
        self.setStyleSheet('''
               * {
                   font-family: Arial, sans-serif;
               }
               QWidget {
                   background-color: #f0f8ff; /* Light blue background */
               }
               QLabel {
                   color: #00008b; /* Dark blue text */
               }
               QLineEdit, QTextEdit, QComboBox, QPushButton {
                   background-color: #ffffff; /* White background */
                   border: 1px solid #00008b; /* Dark blue border */
                   border-radius: 5px; /* Rounded corners */
                   padding: 5px; /* Padding inside the widget */
               }
               QPushButton:hover:!pressed {
                    background-color: #add8e6;
                    color: #000000; /* Black text on hover */
                    font-weight: bold; /* Bold text on hover */
               }
                QMenuBar {
               }
               QMenu {
                   color: #000000; /* Black text for menu items */
               }
               QMenu::item:selected {
                   background-color: #add8e6; /* Light blue background for selected menu item */
               }
           ''')

        # the main layout
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)

        # the user selection page
        self.user_selection_page = QWidget()
        self.initUserSelectionPage()
        self.central_widget.addWidget(self.user_selection_page)

        # Create the rsa generation page
        self.rsa_key_generation_page = QWidget()
        self.initRSAKeyGenerationPage()
        self.central_widget.addWidget(self.rsa_key_generation_page)

        # Show the user selection page initially
        self.central_widget.setCurrentWidget(self.user_selection_page)

    def initUserSelectionPage(self):
        layout = QVBoxLayout()

        # Existing users section
        existing_users_widget = QWidget()
        existing_users_layout = QVBoxLayout()
        existing_users_label = QLabel('Select Existing User:')
        existing_users_label.setStyleSheet('font-size: 20px;')
        self.user_combo = QComboBox()
        self.loadExistingUsers()  # Load existing users from file
        existing_users_layout.addWidget(existing_users_label)
        existing_users_layout.addWidget(self.user_combo)
        existing_users_widget.setLayout(existing_users_layout)
        layout.addWidget(existing_users_widget)

        existing_user_button = QPushButton('Select Existing User')
        existing_user_button.clicked.connect(self.selectExistingUser)
        layout.addWidget(existing_user_button)

        # New user section
        new_user_widget = QWidget()
        new_user_layout = QVBoxLayout()
        new_user_label = QLabel('Create New User:')
        new_user_label.setStyleSheet('font-size: 20px;')
        self.new_user_name_input = QLineEdit()
        self.new_user_name_input.setPlaceholderText('Name')
        new_user_layout.addWidget(new_user_label)
        new_user_layout.addWidget(self.new_user_name_input)
        new_user_widget.setLayout(new_user_layout)
        layout.addWidget(new_user_widget)

        new_user_button = QPushButton('Create New User')
        new_user_button.clicked.connect(self.createNewUser)
        layout.addWidget(new_user_button)

        self.user_selection_page.setLayout(layout)

    def initRSAKeyGenerationPage(self):
        layout = QVBoxLayout()

        # Name
        name_widget = QWidget()
        name_layout = QHBoxLayout()
        name_label = QLabel('Name:')
        self.name_input = QLineEdit()
        name_layout.addWidget(name_label)
        name_layout.addWidget(self.name_input)
        name_widget.setLayout(name_layout)
        layout.addWidget(name_widget)

        # Email
        email_widget = QWidget()
        email_layout = QHBoxLayout()
        email_label = QLabel('Email:')
        self.email_input = QLineEdit()
        email_layout.addWidget(email_label)
        email_layout.addWidget(self.email_input)
        email_widget.setLayout(email_layout)
        layout.addWidget(email_widget)

        # RSA key length
        rsa_key_length_widget = QWidget()
        rsa_key_length_layout = QHBoxLayout()
        rsa_key_length_label = QLabel('RSA Key Length:')
        self.rsa_key_length_spinbox = QSpinBox()
        self.rsa_key_length_spinbox.setRange(1024, 2048)
        self.rsa_key_length_spinbox.setValue(1024)  # Set initial value to 1024
        rsa_key_length_layout.addWidget(rsa_key_length_label)
        rsa_key_length_layout.addWidget(self.rsa_key_length_spinbox)
        rsa_key_length_widget.setLayout(rsa_key_length_layout)
        layout.addWidget(rsa_key_length_widget)

        # Password
        password_widget = QWidget()
        password_layout = QHBoxLayout()
        password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        password_widget.setLayout(password_layout)
        layout.addWidget(password_widget)

        # Generate button
        generate_button = QPushButton('Generate RSA Key Pair')
        generate_button.clicked.connect(self.generateRSAKeyPair)
        layout.addWidget(generate_button, alignment=Qt.AlignRight)

        # Add a status label for showing key generation status
        self.generate_status_label = QLabel('')
        layout.addWidget(self.generate_status_label)

        # Set the layout for the RSA key generation page
        self.rsa_key_generation_page.setLayout(layout)

    def generateRSAKeyPair(self):
        # Function to generate the RSA key pair
        name = self.name_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        rsa_key_length = int(self.rsa_key_length_spinbox.value())

        if not PGPWindow.current_user:
            self.generate_status_label.setText('Error: No user selected.')
            return

        # Generate the RSA key pair
        rings.create_key_pair(PGPWindow.current_user, rsa_key_length, password)
        print(f"Generating RSA key pair for {name} <{email}> with a key length of {rsa_key_length} bits")

        # Update the status label
        self.generate_status_label.setText('RSA key pair generated successfully!')

        # Clear input fields
        self.name_input.clear()
        self.email_input.clear()
        self.password_input.clear()
        self.rsa_key_length_spinbox.setValue(1024)  # Reset to default value

        # Refresh the tables
        self.updatePrivateKeyTable()
        self.updatePublicKeyTable()

    def loadExistingUsers(self):
        base_path = './users'
        if not os.path.exists(base_path):
            os.makedirs(base_path)
        user_folders = [f for f in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, f))]
        user_names = [f.split('_')[-1] for f in user_folders]
        self.user_combo.addItems(user_names)

    def selectExistingUser(self):
        PGPWindow.current_user = self.user_combo.currentText()
        self.show_menu = True  # Show the menu on the main page
        self.initMainPage()
        self.initKeyRingsPage()
        self.initSendingMessagesPage()
        self.central_widget.setCurrentWidget(self.main_page)  # Switch to main page
        self.initMenu()  # Initialize the menu

    def createNewUser(self):
        new_user_name = self.new_user_name_input.text()
        rings.create_user(new_user_name)
        PGPWindow.current_user = new_user_name
        self.show_menu = True  # Show the menu on the main page
        self.initMainPage()
        self.initKeyRingsPage()
        self.initSendingMessagesPage()
        self.central_widget.setCurrentWidget(self.main_page)  # Switch to main page
        self.initMenu()  # Initialize the menu

    def save_message(self, message, id):
        try:
            directory = f'./users/user_{self.current_user}/saved_mails'
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(f'./users/user_{self.current_user}/saved_mails/saved_mail_{id}.txt', 'w') as f:
                f.write(message)
            print("Message saved successfully")
        except Exception as e:
            print(f"Error saving message: {e}")

    def create_message_widget(self, message, id):
        message_widget = QWidget()
        message_layout = QHBoxLayout()

        message_textedit = QTextEdit()
        message_textedit.setReadOnly(True)
        message_textedit.setPlainText(message)

        save_button = QPushButton('Save')
        save_button.clicked.connect(lambda: self.save_message(message, id))

        message_layout.addWidget(message_textedit)
        message_layout.addWidget(save_button)

        message_widget.setLayout(message_layout)
        return message_widget

    def receiveMessage(self):
        recipient = PGPWindow.current_user
        if not recipient:
            print('Error: No user selected.')
            return

        messages = []
        message_files = sorted(glob.glob(f'users/user_{recipient}/mail_e_*.txt'))
        message_ids = []
        for message_file in message_files:
            message_ids.append(message_file.split('_')[-1].split('.')[0])
            try:
                with open(message_file, 'r') as f:
                    message = f.read()
            except Exception as e:
                print(f'Error reading message: {e}')
                return

            # Extract metadata
            metadata = message[:4]
            signing = metadata[0] == '1'
            compression = metadata[1] == '1'
            radix64 = metadata[2] == '1'
            encryption = metadata[3] != '0'
            method = None
            if encryption:
                if metadata[3] == '1':
                    method = 'AES'
                else:
                    method = 'Triple DES'
            message = message[4:]
            if encryption:
                parts = message.split("#_#_#_#")
                message, encrypted_key, key_id = parts[0], int(parts[1]), int(parts[2])

                # Decrypt the session key
                d, n = None, None
                for key in rings.private_key_rings[recipient].values():
                    if key.keyid == key_id:
                        # if rings.check_password(key.keyid, recipient, self.password_input.text()):
                        d, n = key.d, key.n
                        break
                decrypted_key_int = pow(encrypted_key, d, n)
                if method == 'AES':
                    decrypted_key = decrypted_key_int.to_bytes(16, byteorder='big')
                else:
                    decrypted_key = decrypted_key_int.to_bytes(24, byteorder='big')
                if method == 'AES':
                    message = aes128.decrypt_aes128_cfb(message, decrypted_key)
                else:
                    message = tripleDES.decrypt_3des_cfb(message, decrypted_key)
            if radix64:
                message = radix.decode_from_radix64(message)

            if compression:
                message = zipAlg.decompress_string(message)

            if signing:
                parts = message.split("#_#_#_#")
                message, received_hash, key_id = parts[0], int(parts[1]), int(parts[2])
                hash = int(_sha1.sha1(message.encode('utf-8')).hexdigest(), 16)
                valid_signature = False
                for ring in rings.public_key_rings.values():
                    for key in ring.values():
                        if key.keyid == key_id:
                            e, n = key.public_key.e, key.public_key.n
                            decrypted_hash = pow(received_hash, e, n)
                            print(decrypted_hash, hash)
                            if decrypted_hash == hash:
                                valid_signature = True
                                break

                if not valid_signature:
                    message += "\n\nSignature: " + 'Invalid!'
                else:
                    message += "\n\nSignature: " + 'Valid!'
            messages.append(message)

        # Clear existing messages
        for i in reversed(range(self.messages_layout.count())):
            widget = self.messages_layout.itemAt(i).widget()
            if widget is not None:
                widget.setParent(None)

        # Add new messages
        i = 0
        for message in messages:
            message_widget = self.create_message_widget(message, message_ids[i])
            self.messages_layout.addWidget(message_widget)
            i+=1
        self.messages_layout.addStretch()

    def initMainPage(self):
        self.main_page = QWidget()
        layout = QVBoxLayout()

        # Create the received messages section
        received_messages_widget = QWidget()
        received_messages_layout = QVBoxLayout()
        received_messages_label = QLabel('Received Messages')
        received_messages_label.setAlignment(Qt.AlignCenter)
        received_messages_label.setStyleSheet('font-size: 20px;')
        received_messages_layout.addWidget(received_messages_label)

        self.messages_layout = QVBoxLayout()
        self.messages_layout.addStretch()

        scroll_area = QScrollArea()
        scroll_area_widget = QWidget()
        scroll_area_widget.setLayout(self.messages_layout)
        scroll_area.setWidget(scroll_area_widget)
        scroll_area.setWidgetResizable(True)

        received_messages_layout.addWidget(scroll_area)

        received_messages_widget.setLayout(received_messages_layout)
        layout.addWidget(received_messages_widget)

        # Add a refresh button to load the latest received message
        refresh_button = QPushButton('Refresh')
        refresh_button.clicked.connect(self.receiveMessage)
        layout.addWidget(refresh_button, alignment=Qt.AlignRight)

        self.main_page.setLayout(layout)
        self.central_widget.addWidget(self.main_page)
        self.receiveMessage()
    def handleSigningCheckbox(self, state):
        if state == Qt.Checked:
            # Show the pop-up window for selecting the private key
            self.showPrivateKeySelectionPopup()
        else:
            # Hide the pop-up window if it was previously shown
            self.hidePrivateKeySelectionPopup()

    # Add this method to handle the state change of the encryption checkbox
    def handleEncryptionCheckbox(self, state):
        if state == Qt.Checked:
            # Show the pop-up window for selecting the public key
            self.showPublicKeySelectionPopup()
        else:
            # Hide the pop-up window if it was previously shown
            self.hidePublicKeySelectionPopup()

    # Add this method to hide the public key selection popup
    def hidePublicKeySelectionPopup(self):
        if hasattr(self, 'public_popup'):
            self.public_popup.reject()

    def initSendingMessagesPage(self):
        self.send_message_page = QWidget()
        layout = QVBoxLayout()

        # Recipient email
        recipient_widget = QWidget()
        recipient_layout = QHBoxLayout()
        recipient_label = QLabel('To:')
        self.recipient_input = QLineEdit()
        recipient_layout.addWidget(recipient_label)
        recipient_layout.addWidget(self.recipient_input)
        recipient_widget.setLayout(recipient_layout)
        layout.addWidget(recipient_widget)

        # Subject
        subject_widget = QWidget()
        subject_layout = QHBoxLayout()
        subject_label = QLabel('Subject:')
        self.subject_input = QLineEdit()
        subject_layout.addWidget(subject_label)
        subject_layout.addWidget(self.subject_input)
        subject_widget.setLayout(subject_layout)
        layout.addWidget(subject_widget)

        # Message body
        message_widget = QWidget()
        message_layout = QVBoxLayout()
        message_label = QLabel('Message:')
        self.message_input = QTextEdit()
        message_layout.addWidget(message_label)
        message_layout.addWidget(self.message_input)
        message_widget.setLayout(message_layout)
        layout.addWidget(message_widget)

        # Checkbox layout
        checkbox_layout = QHBoxLayout()
        self.encryption_checkbox = QCheckBox('Message encryption')
        self.signing_checkbox = QCheckBox('Message signing')
        self.compression_checkbox = QCheckBox('Message compression')
        self.radix64_checkbox = QCheckBox('Convert to Radix-64 format')
        checkbox_layout.addWidget(self.signing_checkbox)
        checkbox_layout.addWidget(self.compression_checkbox)
        checkbox_layout.addWidget(self.encryption_checkbox)
        checkbox_layout.addWidget(self.radix64_checkbox)
        layout.addLayout(checkbox_layout)

        # Send button
        send_button = QPushButton('Send')
        send_button.clicked.connect(self.sendMessage)
        layout.addWidget(send_button, alignment=Qt.AlignRight)

        # Add a status label for showing message send status
        self.send_status_label = QLabel('')
        layout.addWidget(self.send_status_label)

        # Set the layout for the sending messages page
        self.send_message_page.setLayout(layout)

        # Connect checkbox signals
        self.encryption_checkbox.stateChanged.connect(self.handleEncryptionCheckbox)
        self.signing_checkbox.stateChanged.connect(self.handleSigningCheckbox)
        self.central_widget.addWidget(self.send_message_page)

    def showPrivateKeySelectionPopup(self):
        self.selected_private_keys = []
        self.popup = QDialog(self)
        self.popup.setWindowTitle('Select Private Key')
        self.popup.setGeometry(200, 200, 300, 200)  # Adjusted height for the password input

        layout = QVBoxLayout()

        # Add radio buttons for selecting a private key
        self.private_key_radio_buttons = []
        for key_value in rings.private_key_rings[self.current_user].values():
            radio_button = QRadioButton(f"ID:{key_value.keyid}, Timestamp:{key_value.timestamp}")
            self.private_key_radio_buttons.append(radio_button)
            layout.addWidget(radio_button)

        if self.private_key_radio_buttons:
            self.private_key_radio_buttons[0].setChecked(True)

        # Add a password input field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('Enter Password')
        layout.addWidget(self.password_input)

        # Add a submit button
        submit_button = QPushButton('Submit')
        submit_button.clicked.connect(self.submitPrivateKeySelection)
        layout.addWidget(submit_button)

        self.popup.setLayout(layout)
        self.popup.exec_()

    def submitPrivateKeySelection(self):
        for radio_button in self.private_key_radio_buttons:
            if radio_button.isChecked():
                self.selected_private_keys=[radio_button.text()]

        self.passwordPrivateKeyConf = self.password_input.text()
        if self.passwordPrivateKeyConf:
            print(f"Entered Password: {self.passwordPrivateKeyConf}")
        else:
            print("No password entered.")
            return
        print(f"Selected Private Keys: {self.selected_private_keys}")
        self.popup.accept()

    def showPublicKeySelectionPopup(self):
        self.selected_public_keys = []
        self.selected_encryption_method = None
        self.public_popup = QDialog(self)
        self.public_popup.setWindowTitle('Select Public Key and Encryption Method')
        self.public_popup.setGeometry(200, 200, 300, 250)  # Adjusted size to accommodate additional options

        layout = QVBoxLayout()

        # Create a button group for public key radio buttons
        self.public_key_button_group = QButtonGroup(self.public_popup)
        self.public_key_radio_buttons = []
        for key_value in rings.public_key_rings_current_user.values():
            radio_button = QRadioButton(
                f"ID:{key_value.keyid}, Timestamp:{key_value.timestamp}, User:{key_value.username}")
            self.public_key_radio_buttons.append(radio_button)
            self.public_key_button_group.addButton(radio_button)
            layout.addWidget(radio_button)

        if self.public_key_radio_buttons:
            self.public_key_radio_buttons[0].setChecked(True)

        # Add a label for encryption method selection
        encryption_label = QLabel("Select Encryption Method:")
        layout.addWidget(encryption_label)

        # Create a button group for encryption method radio buttons
        self.encryption_button_group = QButtonGroup(self.public_popup)
        self.encryption_radio_buttons = []
        encryption_methods = ["Triple DES", "AES"]
        for method in encryption_methods:
            radio_button = QRadioButton(method)
            self.encryption_radio_buttons.append(radio_button)
            self.encryption_button_group.addButton(radio_button)
            layout.addWidget(radio_button)

        if self.encryption_radio_buttons:
            self.encryption_radio_buttons[0].setChecked(True)

        # Add a submit button
        submit_button = QPushButton('Submit')
        submit_button.clicked.connect(self.submitPublicKeySelection)
        layout.addWidget(submit_button)

        self.public_popup.setLayout(layout)
        self.public_popup.exec_()

    def submitPublicKeySelection(self):
        selected_public_key = None
        for radio_button in self.public_key_radio_buttons:
            if radio_button.isChecked():
                selected_public_key = radio_button.text()
                break

        selected_encryption_method = None
        for radio_button in self.encryption_radio_buttons:
            if radio_button.isChecked():
                selected_encryption_method = radio_button.text()
                break

        if selected_public_key and selected_encryption_method:
            self.selected_public_keys = [selected_public_key]
            self.selected_encryption_method = selected_encryption_method
            print(f"Selected Public Keys: {self.selected_public_keys}, Selected Method: {self.selected_encryption_method}")
            self.public_popup.accept()
        else:
            print("Error: No selection made.")
    def hidePrivateKeySelectionPopup(self):
        # Implement the logic to hide the pop-up window for selecting the private key
        pass

    def sendMessage(self):
        # Get the input data
        recipient = self.recipient_input.text()
        if recipient not in rings.users:
            self.send_status_label.setText('User doesnt exist!')
            return
        subject = self.subject_input.text()
        message = self.message_input.toPlainText()

        message = "From: "+self.current_user+"\nSubject: "+subject+"\n\n"+message
        # Get the states of the checkboxes
        encryption = self.encryption_checkbox.isChecked()
        signing = self.signing_checkbox.isChecked()
        compression = self.compression_checkbox.isChecked()
        radix64 = self.radix64_checkbox.isChecked()

        # Implement the logic for sending the message
        # print(f"Sending message to: {recipient}")
        # print(f"Subject: {subject}")
        # print(f"Message: {message}")
        # print(f"Encryption: {'Yes' if encryption else 'No'}")
        # print(f"Signing: {'Yes' if signing else 'No'}")
        # print(f"Compression: {'Yes' if compression else 'No'}")
        # print(f"Radix-64: {'Yes' if radix64 else 'No'}")

        if signing:
            hash = int(_sha1.sha1(message.encode('utf-8')).hexdigest(), 16)
            key_id = int(self.selected_private_keys[0].split(',')[0].split(':')[1])
            d, n = None, None
            for key in rings.private_key_rings[self.current_user].values():
                if key.keyid == key_id:
                    if rings.check_password(key.keyid, self.current_user, self.passwordPrivateKeyConf):
                        d, n = key.d, key.n
                    break
            encrypted_hash = pow(hash, d, n)
            message += "#_#_#_#" + str(encrypted_hash)
            message += "#_#_#_#" + str(key_id)

        if compression:
            message = zipAlg.compress_string(message)

        if radix64:
            message = radix.convert_to_radix64(message)

        if encryption:
            generatedKey=None
            if self.selected_encryption_method == 'AES':
                generatedKey = secrets.token_bytes(16)
            else:
                generatedKey = secrets.token_bytes(24)
            key_as_int = int.from_bytes(generatedKey, byteorder='big')
            #key_as_bytes = key_as_int.to_bytes(16, byteorder='big')
            if self.selected_encryption_method == 'AES':
                message = aes128.encrypt_aes128_cfb(message, generatedKey)
            else:
                message = tripleDES.encrypt_3des_cfb(message, generatedKey)
            key_id = int(self.selected_public_keys[0].split(',')[0].split(':')[1])
            e, n = None, None
            for key in rings.public_key_rings[recipient].values():
                if key.keyid == key_id:
                    e, n = key.public_key.e, key.public_key.n
                    break
            encrypted_key = pow(key_as_int, e, n)
            message += "#_#_#_#" + str(encrypted_key)
            message += "#_#_#_#" + str(key_id)

        metadata = ""
        metadata += "1" if signing else "0"
        metadata += "1" if compression else "0"
        metadata += "1" if radix64 else "0"
        if encryption:
            if self.selected_encryption_method == 'AES':
                metadata += "1"
            else:
                metadata += "2"
        else:
            metadata += "0"

        message = metadata + message
        #SENDING
        try:
            with open(f'users/user_{recipient}/mail_e_{rings.users[recipient]}.txt', 'w') as f:
                f.write(message)
                self.send_status_label.setText('Message sent successfully!')
                rings.users[recipient] += 1
                print(rings.users[recipient])
        except Exception as e:
            self.send_status_label.setText(f'Sending error! Error:{e}')


    def initKeyRingsPage(self):
        self.key_rings_page = QWidget()
        layout = QVBoxLayout()

        # Create the private key ring part
        private_key_ring_widget = QWidget()
        private_key_ring_layout = QVBoxLayout()
        private_key_ring_label = QLabel('Private Key Ring')
        private_key_ring_label.setAlignment(Qt.AlignCenter)
        private_key_ring_label.setStyleSheet('font-size: 20px;')
        private_key_ring_layout.addWidget(private_key_ring_label)

        self.private_key_table = QTableWidget()
        self.private_key_table.setColumnCount(9)
        self.private_key_table.setHorizontalHeaderLabels(
            ['Timestamp', 'Key ID', 'Public Key', 'Private Key', 'n', 'Username', '', '', ''])
        self.private_key_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.private_key_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        private_key_ring_layout.addWidget(self.private_key_table)

        # Add import button for private keys
        import_private_key_button = QPushButton('Import Key Pair')
        import_private_key_button.clicked.connect(self.importKeyPair)
        private_key_ring_layout.addWidget(import_private_key_button)

        private_key_ring_widget.setLayout(private_key_ring_layout)

        # Create the public key ring part
        public_key_ring_widget = QWidget()
        public_key_ring_layout = QVBoxLayout()
        public_key_ring_label = QLabel('Public Key Ring')
        public_key_ring_label.setAlignment(Qt.AlignCenter)
        public_key_ring_label.setStyleSheet('font-size: 20px;')
        public_key_ring_layout.addWidget(public_key_ring_label)

        self.public_key_table = QTableWidget()
        self.public_key_table.setColumnCount(5)
        self.public_key_table.setHorizontalHeaderLabels(
            ['Timestamp', 'Key ID', 'n', 'Username', ''])
        self.public_key_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.public_key_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        public_key_ring_layout.addWidget(self.public_key_table)

        # Add import button for public keys
        import_public_key_button = QPushButton('Import Public Key')
        import_public_key_button.clicked.connect(self.importPublicKey)
        public_key_ring_layout.addWidget(import_public_key_button)

        public_key_ring_widget.setLayout(public_key_ring_layout)

        # Add the private key ring widget at the top and the public key ring widget at the bottom
        layout.addWidget(private_key_ring_widget, alignment=Qt.AlignTop)
        layout.addWidget(public_key_ring_widget, alignment=Qt.AlignTop)

        self.key_rings_page.setLayout(layout)
        self.central_widget.addWidget(self.key_rings_page)

        # Initial population of the tables
        self.updatePrivateKeyTable()
        self.updatePublicKeyTable()

    def updatePrivateKeyTable(self):
        if not PGPWindow.current_user or PGPWindow.current_user not in rings.private_key_rings:
            return

        private_key_rings = rings.private_key_rings[PGPWindow.current_user]
        self.private_key_table.setRowCount(len(private_key_rings))

        for row, key in enumerate(private_key_rings.values()):
            self.private_key_table.setItem(row, 0, QTableWidgetItem(str(key.timestamp)))
            self.private_key_table.setItem(row, 1, QTableWidgetItem(str(key.keyid)))
            self.private_key_table.setItem(row, 2, QTableWidgetItem(str(key.public_key)))
            self.private_key_table.setItem(row, 3, QTableWidgetItem(str(key.private_key)[:20]))
            self.private_key_table.setItem(row, 4, QTableWidgetItem(str(key.n)))
            self.private_key_table.setItem(row, 5, QTableWidgetItem(key.username))

            delete_button = QPushButton('Delete')
            delete_button.clicked.connect(lambda ch, k=key.keyid: self.deleteKeyPair(k))
            self.private_key_table.setCellWidget(row, 6, delete_button)

            export_button = QPushButton('Export Pair')
            export_button.clicked.connect(lambda ch, k=key.keyid: self.exportKeyPair(k))
            self.private_key_table.setCellWidget(row, 7, export_button)

            export_button2 = QPushButton('Export Public')  # Corrected variable name
            export_button2.clicked.connect(lambda ch, k=key.keyid: self.exportPublicKey(k))
            self.private_key_table.setCellWidget(row, 8, export_button2)

    def updatePublicKeyTable(self):
        if not PGPWindow.current_user:
            return
        if not self.public_keys_loaded:
            rings.load_public_key_rings(PGPWindow.current_user)
            self.public_keys_loaded=True
        public_key_rings = rings.public_key_rings_current_user
        self.public_key_table.setRowCount(len(public_key_rings))

        for row, key in enumerate(public_key_rings.values()):
            self.public_key_table.setItem(row, 0, QTableWidgetItem(str(key.timestamp)))
            self.public_key_table.setItem(row, 1, QTableWidgetItem(str(key.keyid)))
            self.public_key_table.setItem(row, 2, QTableWidgetItem(str(key.public_key.n)))
            self.public_key_table.setItem(row, 3, QTableWidgetItem(key.username))

            delete_button = QPushButton('Delete')
            delete_button.clicked.connect(lambda ch, k=key.keyid: self.deletePublicKey(k))
            self.public_key_table.setCellWidget(row, 4, delete_button)

    def deleteKeyPair(self, keyid):
        # Implement the logic to delete a private key
        if PGPWindow.current_user in rings.private_key_rings and keyid in rings.private_key_rings[
            PGPWindow.current_user]:
            rings.delete_key_pair(self.current_user, keyid)
            self.updatePublicKeyTable()
            self.updatePrivateKeyTable()

    def deletePublicKey(self, keyid):
        if keyid in rings.public_key_rings_current_user:
            del rings.public_key_rings_current_user[keyid]
            self.updatePublicKeyTable()
            self.updatePrivateKeyTable()
            rings.save_personal_public_keys(self.current_user)

    def exportPublicKey(self, keyid):
        if PGPWindow.current_user in rings.public_key_rings and keyid in rings.public_key_rings[PGPWindow.current_user]:
            rings.export_key_to_pem(self.current_user, keyid)

    def exportKeyPair(self, keyid):
        password, ok_pressed = QInputDialog.getText(self, 'Password Input', 'Enter Password:', QLineEdit.Password)
        if ok_pressed:
            if rings.check_password(keyid, self.current_user, password):
                rings.export_keypair_to_pem(PGPWindow.current_user, keyid, password)
            else:
                QMessageBox.warning(self, 'Password Incorrect', 'Incorrect password. Please try again.', QMessageBox.Ok)

    def importKeyPair(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import Public Key", "", "All Files (*);;Text Files (*.txt)",
                                                   options=options)
        print(file_name)

        if file_name:
            try:
                rings.import_datapair_from_pem(file_name, self.current_user)
                QMessageBox.information(self, 'Success', 'Key pair imported successfully!')
                self.updatePublicKeyTable()
                self.updatePrivateKeyTable()
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to import key pair: {e}')

    def importPublicKey(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import Key Pair", "", "All Files (*);;Text Files (*.txt)",
                                                   options=options)
        print(file_name)

        if file_name:
            try:
                rings.import_data_from_pem(file_name)
                QMessageBox.information(self, 'Success', 'Public key imported successfully!')
                self.updatePublicKeyTable()
                self.updatePrivateKeyTable()
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to import public key: {e}')

    def initMenu(self):
        if not self.show_menu:
            return

        menubar = self.menuBar()
        menu = menubar.addMenu('Menu')

        receiving_messages_action = QAction('Received Messages', self)
        receiving_messages_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.main_page))
        menu.addAction(receiving_messages_action)

        key_rings_action = QAction('Key Rings', self)
        key_rings_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.key_rings_page))
        menu.addAction(key_rings_action)

        sending_messages_action = QAction('Sending Messages', self)
        sending_messages_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.send_message_page))
        menu.addAction(sending_messages_action)

        rsa_key_generation_action = QAction('RSA Key Generation', self)
        rsa_key_generation_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.rsa_key_generation_page))
        menu.addAction(rsa_key_generation_action)
        def funkcija():
            pass

        quit_action = QAction('Quit', self)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)


def main():
    app = QApplication(sys.argv)
    window = PGPWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
