# DSA-Mini-Project-AES
## Name: PATIL AKASH M.
## MIS No: 111503075
## AES Encryption using C
  This program encrypts/decrypts given text file using Advanced Encryption Standard
  (AES) symmectric algorithm.

### About Project
  <ul>
    <li>AES algorithm encrypts data block of 16 Byte at a time</li>
    <li>If data block is not of 16 byte padding is done.</li>
    <li><em>PKCS#5 Padding</em> is used</li>
    <li>AES use same Key for encryption and decryption</li>
    <li>This Program takes input as text file from user and encrypts data</li>
    <li>Using same key user can decrypt data again</li>
   </ul>

### Usage
  <ul>
      $ make
    <li>For Help</li>
      $ ./program -h<br>
     <li>For Encryption</li>
      $ ./program -e filename1 filename2<br>
     <li>For Decryption</li>
      $ ./program -d filename1 filename2<br>
  </ul>
### Reference
  <ul>
    <li>Cryptography Network Security by Forouzan</li>
  <ul>
