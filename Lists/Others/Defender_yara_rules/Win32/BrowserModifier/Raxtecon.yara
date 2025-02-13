rule BrowserModifier_Win32_Raxtecon_228516_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Raxtecon"
        threat_id = "228516"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Raxtecon"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\condefsetup.log" ascii //weight: 1
        $x_1_2 = "\\Content Defender" ascii //weight: 1
        $x_1_3 = "\\condefrm.bat" ascii //weight: 1
        $x_1_4 = "ContentDefender\\Release\\condefclean.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Raxtecon_228516_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Raxtecon"
        threat_id = "228516"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Raxtecon"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Web Content Blocked by Content Defender" ascii //weight: 1
        $x_1_2 = "ConDefSetup.exe" ascii //weight: 1
        $x_1_3 = "contentdefenderdrv.sys" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 63 6f 6e 74 65 6e 74 64 65 66 65 6e 64 65 72 2d 05 00 2e 6f 72 67 2f 76 65 72 73 69 6f 6e 2f 63 68 65 63 6b 6e 65 77 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Raxtecon_228516_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Raxtecon"
        threat_id = "228516"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Raxtecon"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Content Defender Setup" wide //weight: 1
        $x_1_2 = "Content Defender Administration" wide //weight: 1
        $x_1_3 = "ContentDefenderControl" wide //weight: 1
        $x_1_4 = "contentdefenderdrv.sys" wide //weight: 1
        $x_1_5 = "ContentDefender.exe" wide //weight: 1
        $x_1_6 = "ConDefSe.exe" wide //weight: 1
        $x_1_7 = "Artex Management" wide //weight: 1
        $x_1_8 = {63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2d 00 [0-16] 2f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2f 00 63 00 68 00 65 00 63 00 6b 00 6e 00 65 00 77 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Raxtecon_228516_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Raxtecon"
        threat_id = "228516"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Raxtecon"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Content Protector Setup Wizard" wide //weight: 1
        $x_1_2 = "ContentProtectorConrol.exe" wide //weight: 1
        $x_1_3 = "ContentProtectorUpdate.exe" wide //weight: 1
        $x_1_4 = "ContentProtectorDrv.sys" wide //weight: 1
        $x_1_5 = "ContentProtector.exe" wide //weight: 1
        $x_1_6 = "ConProtSe.exe" wide //weight: 1
        $x_1_7 = "Artex Management" wide //weight: 1
        $x_1_8 = "full_installer_url" wide //weight: 1
        $x_1_9 = {63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 2d 00 [0-16] 2f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2f 00 63 00 68 00 65 00 63 00 6b 00 6e 00 65 00 77 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

