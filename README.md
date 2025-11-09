<table border="0">
 <tr>
    <td style="width:300px; vertical-align:middle; text-align:center;">
      <img src="https://upload.wikimedia.org/wikipedia/commons/e/e1/University_of_Prishtina_logo.svg" 
           alt="University Logo" 
           style="width:250px; height:auto;" />
    </td>
    <td style="vertical-align:middle; padding-left:20px;">
      <h2><strong>Universiteti i Prishtinës</strong></h2>
      <h3>Fakulteti i Inxhinierisë Elektrike dhe Kompjuterike</h3>
      <p>Inxhinieri Kompjuterike dhe Softuerike - Programi Master</p>
      <p><strong>Profesor:</strong> Prof. Dr. Blerim Rexha</p>
      <p><strong>Asistent:</strong> Dr.Sc. Mërgim H. HOTI</p>
    </td>
 </tr>
</table>


# Introduction

The purpose of this project is to demonstrate how passwords can be securely stored and verified using the PBKDF2-SHA1 algorithm in Python.  
Traditional password hashing methods such as MD5 or SHA1 alone are vulnerable to brute-force and rainbow-table attacks. PBKDF2 (Password-Based Key Derivation Function 2) increases security by applying a cryptographic hash multiple times and adding a random salt, making attacks computationally expensive and impractical.

This implementation shows how to generate a strong salted hash for a user’s password and later verify it safely without ever storing or comparing the password in plain text.
