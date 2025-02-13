rule Ransom_Win64_FonixCrypter_PA_2147761566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FonixCrypter.PA!MTB"
        threat_id = "2147761566"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FonixCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XinofSetup.bat" wide //weight: 1
        $x_1_2 = "How To Decrypt Files.hta" wide //weight: 1
        $x_1_3 = "\\Help.txt" wide //weight: 1
        $x_1_4 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\XINOF.exe" ascii //weight: 1
        $x_1_5 = "/c vssadmin Delete Shadows /All /Quiet & wmic shadowcopy delete" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\XINOFBG.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

