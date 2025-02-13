rule BrowserModifier_Win32_My123_17550_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/My123"
        threat_id = "17550"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "My123"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "%s&pid=%s&mid=%s" ascii //weight: 3
        $x_3_2 = "%s?pid=%s&mid=%s" ascii //weight: 3
        $x_3_3 = {25 73 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 5c 25 73 22 2c 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 00 00 53 6f 66 74 77 61 72 65 5c [0-9] 5c 55 70 64 61 74 65 00 [0-9] 00 7b 25 30 38 6c 58 2d 25 30 34 58 2d 25 30 34 78 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}  //weight: 3, accuracy: Low
        $x_3_4 = "http://www.my123.com/" ascii //weight: 3
        $x_3_5 = "aHR0cDovL" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_My123_17550_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/My123"
        threat_id = "17550"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "My123"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\SystemRoot\\system32\\drivers\\%s.sys" ascii //weight: 3
        $x_3_2 = "\\SystemRoot\\system32\\%s.dll" ascii //weight: 3
        $x_5_3 = "%%systemroot%%\\system32\\Rundll32.exe %%systemroot%%\\system32\\%s.dll,DllUnregisterServer" ascii //weight: 5
        $x_5_4 = "%%systemroot%%\\system32\\Rundll32.exe %%systemroot%%\\system32\\%s.dll,DllCanUnloadNow" ascii //weight: 5
        $x_5_5 = "http://www.my123.com/" ascii //weight: 5
        $x_10_6 = "\\sys\\objfre_w2K_x86\\i386\\autolive.pdb" ascii //weight: 10
        $x_3_7 = "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce" wide //weight: 3
        $x_3_8 = "Start Page" wide //weight: 3
        $x_3_9 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 3
        $x_10_10 = "http://www.my123.com/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

