rule Ransom_Win32_Rackcrypt_A_2147708594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rackcrypt.A"
        threat_id = "2147708594"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rackcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We are sorry to tell you, but  all your files on this PC" wide //weight: 1
        $x_1_2 = "and you can personaly verify this by pressing  \"files\"" wide //weight: 1
        $x_1_3 = "IDC_STATIC_WALLET" wide //weight: 1
        $x_1_4 = "Use \"copy\" button to copy wallet address to clipboard." wide //weight: 1
        $x_1_5 = "In case you made a payment, but decryption process" wide //weight: 1
        $x_1_6 = "encrypted using strongest AES-256 encryption algorithm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

