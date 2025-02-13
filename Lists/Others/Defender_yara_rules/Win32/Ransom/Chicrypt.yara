rule Ransom_Win32_Chicrypt_A_2147707376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chicrypt.A"
        threat_id = "2147707376"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chicrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You can reach us via the bitmessage address:" ascii //weight: 1
        $x_1_2 = "Chimera" ascii //weight: 1
        $x_1_3 = "%s.crypt" ascii //weight: 1
        $x_1_4 = "\\YOUR_FILES_ARE_ENCRYPTED.HTML" ascii //weight: 1
        $x_1_5 = "pay your private data, which include pictures and videos will be published on the internet" ascii //weight: 1
        $x_1_6 = "You are victim of the Chimera" ascii //weight: 1
        $x_1_7 = "<title>Chimera&reg; Ransomware</title>" ascii //weight: 1
        $x_1_8 = "Sie wurden Opfer der Chimera Malware." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

