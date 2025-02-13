rule Ransom_Win32_Buran_A_2147747906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Buran.A!MSR"
        threat_id = "2147747906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Buran"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 55 52 41 4e [0-32] 53 54 4f 52 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "Uninstall/disable all antivirus (and Windows Defender) before using this" ascii //weight: 1
        $x_1_3 = "Software\\Buran V\\Stop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Buran_PAA_2147773637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Buran.PAA!MTB"
        threat_id = "2147773637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Buran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "<\\\" -start\"EG_SZ /F /D \"\\\"ority Subsystem Servicedows\\CurrentVersion\\Run\" /V \"" wide //weight: 10
        $x_10_2 = "QUICK >>> UNDECRYPTABLE >>> ENCRYPTING RANDOM FILEBLOCKS /// THIS IS BURAN /// GENERATION" ascii //weight: 10
        $x_10_3 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"" wide //weight: 10
        $x_10_4 = "Software\\Buran V\\Service\\Public Key" ascii //weight: 10
        $x_10_5 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 10
        $x_10_6 = "lsass.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

