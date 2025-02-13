rule Trojan_Win32_Dtasioa_A_2147904924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dtasioa.A"
        threat_id = "2147904924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dtasioa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 6d 00 00 04 06 7e 6d 00 00 04 06 91 06 61 20 aa 00 00 00 61 d2 9c 06 17 58 0a}  //weight: 1, accuracy: High
        $x_1_2 = "1E98FFC6-75C7-4B24-B661-553342352B8B" ascii //weight: 1
        $x_1_3 = "E105F4E4-0F49-4819-8B9C-837273E4949F" ascii //weight: 1
        $x_1_4 = "paper-wallet-*.png" ascii //weight: 1
        $x_1_5 = "Screenshot failed" ascii //weight: 1
        $x_1_6 = "Failed parsing cfg" ascii //weight: 1
        $x_1_7 = "Second stage size: {0}" ascii //weight: 1
        $x_1_8 = "Jaxx\\Local Storage\\wallet.dat" ascii //weight: 1
        $x_1_9 = "peerPublicKey must be null or 32 bytes long" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

