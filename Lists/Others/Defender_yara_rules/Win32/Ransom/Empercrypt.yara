rule Ransom_Win32_Empercrypt_A_2147708730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Empercrypt.A"
        threat_id = "2147708730"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Empercrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /delete /TN uac /F" ascii //weight: 1
        $x_1_2 = "YOUR PERSONAL INFORMATION ARE ENCRYPTED by 7ev3n" ascii //weight: 1
        $x_1_3 = "bcdedit /set {current} recoveryenabled off" ascii //weight: 1
        $x_1_4 = "blockchain.info/api/receive?method=create&address=" wide //weight: 1
        $x_1_5 = "FILES_BACK.txt" wide //weight: 1
        $x_1_6 = "?SSTART=true&CRYPTED_DATA=" wide //weight: 1
        $x_1_7 = "fgate.php?RIGHTS=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

