rule Ransom_Win32_Seelcrypt_A_2147721600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Seelcrypt.A"
        threat_id = "2147721600"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Seelcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@bitmessage.ch" ascii //weight: 2
        $x_1_2 = "WRITE TO THIS E-MAIL ADRESS:" ascii //weight: 1
        $x_1_3 = "Your computer was attacked by trojan called cryptolocker. All your files are encrypted with cryptographically strong algorithm, and without original decryption key recovery is impossible." ascii //weight: 1
        $x_1_4 = "To get your unique key and decode your files, you need to write us at email written below during 72 hours,  otherwise your files will be destroyed forever!" ascii //weight: 1
        $x_2_5 = {00 64 65 73 6b 31 2e 62 6d 70 00}  //weight: 2, accuracy: High
        $x_1_6 = {00 63 68 63 70 20 31 32 35 31 20 3e 20 6e 75 6c 20 00}  //weight: 1, accuracy: High
        $x_3_7 = "bin:com:exe:bat:png:bmp:dat:log:ini:dll:sys:" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

