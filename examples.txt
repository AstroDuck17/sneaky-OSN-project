Examples
Note: There is no specification on the exact format of the commands. The commands mentioned in the examples are indicative. You may choose to implement them in any format you like, as long as the functionality remains the same.

Example 1: View File
Client: VIEW  # Lists files accessible to the user
--> wowee.txt
--> nuh_uh.txt

Client: VIEW -a  # Lists all files on the system
--> wowee.txt
--> nuh_uh.txt
--> grades.txt

Client: VIEW -l  # Lists files accessible to the user with details
---------------------------------------------------------
|  Filename  | Words | Chars | Last Access Time | Owner |
|------------|-------|-------|------------------|-------|
| wowee.txt  |   69  |  420  | 2025-10-10 14:32 | user1 |
| nuh_uh.txt |   37  |  123  | 2025-10-10 14:32 | user1 |
---------------------------------------------------------

Client: VIEW -al
---------------------------------------------------------
|  Filename  | Words | Chars | Last Access Time | Owner |
|------------|-------|-------|------------------|-------|
| wowee.txt  |   69  |  420  | 2025-10-10 14:32 | user1 |
| nuh_uh.txt |   37  |  123  | 2025-10-10 14:32 | user1 |
| grades.txt |   51  |  273  | 2025-10-10 14:32 | kaevi |
---------------------------------------------------------
Example 2: Read File
Client: READ wowee.txt  # Displays the content of the file
OSN assignments are so fun!

I love doing them.          Wish we had more of them.
Example 3: Create File
Client: CREATE mouse.txt  # Creates an empty file named mouse.txt
File Created Successfully!

Client: VIEW
--> wowee.txt
--> nuh_uh.txt
--> mouse.txt
Note: NS dynamically adds the new file to the list of available files and updates backup SSs. If the file already exists, NS responds with an appropriate error.

Example 4: Write to a File
Client: WRITE mouse.txt 0 # Adding to the start of file
Client: 1 Im just a mouse.
Client: ETIRW
Write Successful!

Client: READ mouse.txt
Im just a mouse.

Client: WRITE mouse.txt 1  # In essence, appending to the file
Client: 1 I dont like PNS
Client: ETIRW
Write Successful!

Client: READ mouse.txt
Im just a mouse. I dont like PNS

Client WRITE mouse.txt 2  # Caveat, note the lack of delimiter after last sentence. There are only 2 sentences.
ERROR: Sentence index out of range.  # Similarly for word indexes (negative or > number of words + 1, should results in errors)

Client: WRITE mouse.txt 1  # Inserting into the second sentence
Client: 3 T-T
Client: ETIRW
Write Successful!

Client: READ mouse.txt
Im just a mouse. I dont like T-T PNS

Client: WRITE mouse.txt 0  # Inserting multiple times into a sentence
Client: 4 deeply mistaken hollow lil gei-fwen # New sentence : Im just a deeply mistaken hollow lil gei-fwen pocket-sized mouse.
Client: 6 pocket-sized  # New sentence : Im just a deeply mistaken hollow pocket-sized lil gei-fwen mouse.
Client: ETIRW
Write Successful!

Client: READ mouse.txt
Im just a deeply mistaken hollow pocket-sized lil gei-fwen mouse. I dont like T-T PNS

Client: WRITE mouse.txt 1  # Inserting a sentence delimiter
Client: 5 and AAD. aaaah # New sentences : [I dont like T-T PNS and AAD.]* [aaaah]. Currently active status remains with the index at index 1
Client: 0 But,  # New sentence : [But, I dont like T-T PNS and AAD.]* [aaaah].
Client: ETIRW
Write Successful!

Client: READ mouse.txt
Im just a deeply mistaken hollow pocket-sized lil gei-fwen mouse. But, I dont like T-T PNS and AAD. aaaah.
The multiples writes within a single WRITE call, are all considered a single operation. Note this while implementing features like UNDO

Proper error handling should cover:

Attempting to write without access
Attempting to write a locked sentence
Invalid indices
Updates are applied in order received, so later updates operate on the already modified sentence.
Example 5: Undo Change
Client: READ nuh uh.txt
rm -rf /  # Oops!

Client: WRITE nuh_uh.txt 0
Client: 0 sudo
Client: ETIRW
Write Successful!

Client: READ nuh_uh.txt
sudo rm -rf /

Client: UNDO nuh_uh.txt
Undo Successful!

Client: READ nuh_uh.txt
rm -rf /
Note:

Only one undo operation for a file needs to be supported. Multiple undos are beyond the scope of this project.
Undo operates at the Storage Server level and only reverts the most recent change.
If the current user is user1 and the most recent modification to the file was made by user2, then an UNDO command issued by user1 should revert user2’s last change.
Example 6: Get Additional Information
Client: INFO nuh_uh.txt
--> File: feedback.txt
--> Owner: user1
--> Created: 2025-10-10 14:21
--> Last Modified: 2025-10-10 14:32
--> Size: 52 bytes
--> Access: user1 (RW)
--> Last Accessed: 2025-10-10 14:32 by user1
Example 7: Delete a File
Client: VIEW
--> wowee.txt
--> nuh_uh.txt
--> mouse.txt

Client: DELETE mouse.txt
File 'mouse.txt' deleted successfully!

Client: VIEW
--> wowee.txt
--> nuh_uh.txt
Example 8: Stream File
Same as READ, but the client receives the file content word-by-word (from the storage server) with a delay of 0.1 seconds between each word.

Example 9: List Users
Client: LIST
--> user1
--> user2
--> kaevi
Example 10: Access Control
Client: INFO nuh_uh.txt
--> File: feedback.txt
--> Owner: user1
--> Created: 2025-10-10 14:21
--> Last Modified: 2025-10-10 14:32
--> Size: 52 bytes
--> Access: user1 (RW)
--> Last Accessed: 2025-10-10 14:32 by user1

Client: ADDACCESS -R nuh_uh.txt user2
Access granted successfully!

Client: INFO nuh_uh.txt
--> File: feedback.txt
--> Owner: user1
--> Created: 2025-10-10 14:21
--> Last Modified: 2025-10-10 14:32
--> Size: 52 bytes
--> Access: user1 (RW), user2 (R)
--> Last Accessed: 2025-10-10 14:32 by user1

Client: ADDACCESS -W nuh_uh.txt user2
Access granted successfully!

--> File: feedback.txt
--> Owner: user1
--> Created: 2025-10-10 14:21
--> Last Modified: 2025-10-10 14:32
--> Size: 52 bytes
--> Access: user1 (RW), user2 (RW)
--> Last Accessed: 2025-10-10 14:32 by user1

Client: REMACCESS nuh_uh.txt user2
Access removed successfully!

Client: INFO nuh_uh.txt
--> File: feedback.txt
--> Owner: user1
--> Created: 2025-10-10 14:21
--> Last Modified: 2025-10-10 14:32
--> Size: 52 bytes
--> Access: user1 (RW)
--> Last Accessed: 2025-10-10 14:32 by user1
Example 11: Execute File
Suppose the content of LMAAO.txt is as follows:

echo "Running diagnostics..."
ls
echo "Done!"
Client: EXEC LMAAO.txt
Running siagnostics...
--> LMAAO.txt
--> RotT.txt
--> AUG.txt
Done!
