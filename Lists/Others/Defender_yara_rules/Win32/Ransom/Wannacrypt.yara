rule Ransom_Win32_Wannacrypt_AA_2147746102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannacrypt.AA!MSR"
        threat_id = "2147746102"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannacrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware Snc.exe" ascii //weight: 1
        $x_1_2 = "WCry\\WCry\\Banner\\WpfApp1\\obj\\Release\\Ransomware Snc.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Wannacrypt_AA_2147751477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannacrypt.AA!MTB"
        threat_id = "2147751477"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannacrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaCry Ransomware" ascii //weight: 1
        $x_1_2 = "Your important files are encrypted." ascii //weight: 1
        $x_1_3 = "Payment is accepted in Bitcoins only." ascii //weight: 1
        $x_1_4 = "Local drive, Ram & Bootloader Bios has been encrypted" ascii //weight: 1
        $x_1_5 = "You need pay 0,02 BTC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

