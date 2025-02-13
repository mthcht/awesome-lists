rule Rogue_Win32_FakeXPA_18119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = "This program will download and install XP Antivirus on your PC." ascii //weight: 11
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antivirus 2009 - Threats detected" ascii //weight: 1
        $x_1_2 = "scui.cpl" ascii //weight: 1
        $x_1_3 = "Scan IE cookies" ascii //weight: 1
        $x_1_4 = "$$$$.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {51 57 50 72 6f 74 65 63 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_1_2 = "QWProtectBHO" ascii //weight: 1
        $x_1_3 = {74 12 6a 02 6a 00 6a 00 8b 45 08 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {83 e1 fd 8b 55 08 c1 fa 05 8b 45 08 83 e0 1f c1 e0 06}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 61 00 6e 00 74 00 79 00 00 00 00 00 61 00 6e 00 74 00 69 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://winantiviruspro.net/buy.php?affid=" ascii //weight: 10
        $x_10_2 = "745270E7-449E-467E-91EA-143DEA260B22" ascii //weight: 10
        $x_10_3 = "Spyware.IEMonster activity detected." ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Windows Alert!" ascii //weight: 1
        $x_1_2 = "Critical System Warning!" ascii //weight: 1
        $x_1_3 = "Your system is probably infected with version of Spyware.IEMonster.b." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 00 68 00 6f 00 73 00 74 00 00 00 38 00 00 00 53 00 65 00 74 00 75 00 70 00 20 00 2d 00 20 00 45 00 2d 00 53 00 65 00 74 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 31 00 31 00 00 00 00 00 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 73 00 76 00 63 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This program will download and install Antivirus" ascii //weight: 1
        $x_1_2 = "Accordingly to technical reason it's impossible to download and install the free version" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{8B1E6256-6C3C-442c-9B28-E526EA2E73F6}" ascii //weight: 1
        $x_1_2 = "://scanreporting.com" ascii //weight: 1
        $x_1_3 = "BuyDiscUrl" ascii //weight: 1
        $x_1_4 = "www.WinDesktopDefender.com/" ascii //weight: 1
        $x_1_5 = "Desktop Defender 2010" ascii //weight: 1
        $x_1_6 = "installer-mutex-" ascii //weight: 1
        $x_1_7 = "/httpss/setup.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 00 00 54 68 69 73 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 41 6e 74 69 76 69 72 75 73 20 32 30 30 39 20 6f 6e 20 79 6f 75 72 20 50 43 2e}  //weight: 1, accuracy: High
        $x_1_2 = {05 00 00 00 66 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 00 00 42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50}  //weight: 1, accuracy: High
        $x_1_4 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_5 = "URLOpenStreamA" ascii //weight: 1
        $x_1_6 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".php?step=" wide //weight: 1
        $x_1_2 = "\\{F275E931-AFEC-4f70-B0D4-CC2731B945E0}" wide //weight: 1
        $x_1_3 = "\\AVInstaller" ascii //weight: 1
        $x_1_4 = "_inst_dl_failure" wide //weight: 1
        $x_1_5 = "_stage_one_complete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4a 61 76 61 53 63 72 69 70 74 00 00 73 61 79 48 65 6c 6c 6f 28 29}  //weight: 2, accuracy: High
        $x_2_2 = {49 45 44 65 66 65 6e 64 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_1_3 = "3C40236D-990B-443C-90E8-B1C07BCD4A68" wide //weight: 1
        $x_1_4 = "F275E931-AFEC-4f70-B0D4-CC2731B945E0" wide //weight: 1
        $x_1_5 = "/index.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/presale/2/index.php?id=" ascii //weight: 10
        $x_10_2 = "{D62C9560-0180-47ea-A3E3-666BC0FE41CC}" ascii //weight: 10
        $x_10_3 = "/admin/cgi-bin/get_domain.php?type=site" wide //weight: 10
        $x_5_4 = "/blocked.php?id=" ascii //weight: 5
        $x_5_5 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 79 00 73 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {61 00 6e 00 74 00 69 00 76 00 79 00 72 00 75 00 73 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {61 00 6e 00 74 00 79 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{3539DFE8-6BE9-44a3-8E78-44DBAE5BDC13}" wide //weight: 1
        $x_1_2 = "{84283E6B-C377-498f-BF91-698E877555CC}" wide //weight: 1
        $x_1_3 = "/admin/cgi-bin/get_domain.php?type=" wide //weight: 1
        $x_1_4 = "/updater.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/en/exe/IEDefender.dll" ascii //weight: 2
        $x_2_2 = "You need to have internet access to download and install the free version of Antivirus 20" ascii //weight: 2
        $x_1_3 = "You must have admin rights!" ascii //weight: 1
        $x_1_4 = "/en/exe/AV2010.exe" ascii //weight: 1
        $x_1_5 = "Software\\AV2010\\AV2010\\" ascii //weight: 1
        $x_1_6 = "\\wingamma.exe" ascii //weight: 1
        $x_1_7 = "get.php?step=" ascii //weight: 1
        $x_1_8 = "/buy.php" ascii //weight: 1
        $x_1_9 = "_hostfile_does_not_exist_" ascii //weight: 1
        $x_1_10 = "_generate_clone_" ascii //weight: 1
        $x_1_11 = "_install_run_" ascii //weight: 1
        $x_1_12 = "reviews.riverstreams.co.uk" ascii //weight: 1
        $x_1_13 = "reviews.techradar.com" ascii //weight: 1
        $x_1_14 = "softwarereviews.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/presale/2/index.php?id=" wide //weight: 10
        $x_10_2 = "{F275E931-AFEC-4f70-B0D4-CC2731B945E0}" wide //weight: 10
        $x_10_3 = "Internet Explorer has found an unregistered version of Antivirus 2010." wide //weight: 10
        $x_5_4 = "/blocked.php?id=" wide //weight: 5
        $x_5_5 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 79 00 73 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {61 00 6e 00 74 00 69 00 76 00 79 00 72 00 75 00 73 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {61 00 6e 00 74 00 79 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/admin/cgi-bin/check_update.php?type=site" ascii //weight: 3
        $x_2_2 = "collection.php?step=" wide //weight: 2
        $x_2_3 = "/afterscan.php?id=%s" wide //weight: 2
        $x_1_4 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "Spyware.IEMonster activity detected." wide //weight: 1
        $x_1_7 = "|EXEPATH|" wide //weight: 1
        $x_1_8 = "detected internal software conflict." wide //weight: 1
        $x_3_9 = "/collection.php?step=AV_uninstall_complete&id=%s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_2 = "/admin/cgi-bin/get_domain.php" wide //weight: 10
        $x_1_3 = "Software\\AV1\\AV1\\" wide //weight: 1
        $x_1_4 = "AV19_stage_one_complete" wide //weight: 1
        $x_1_5 = "AV19_inst_run_failure" wide //weight: 1
        $x_1_6 = "AV19_inst_dl_failure" wide //weight: 1
        $x_1_7 = "AV19_inst2_dl_failure" wide //weight: 1
        $x_1_8 = "AV1i.exe" wide //weight: 1
        $x_1_9 = "AV1Two.exe" wide //weight: 1
        $x_1_10 = "Anti-virus-1" wide //weight: 1
        $x_1_11 = "AV19_install_run" wide //weight: 1
        $x_1_12 = "AV19_GetId_failure" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "***STOP: 0x000000D1 (0x00000000, 0xF73120AE, 0xC0000008, 0xC0000000)" ascii //weight: 2
        $x_2_2 = "*** SRV.SYS - Address F73120AE base at C0000000, DateStamp 36b072a3" ascii //weight: 2
        $x_2_3 = "A spyware application has been detected and Windows has been shut down to" ascii //weight: 2
        $x_2_4 = "SPYWARE.MONSTER.FX_WILD_0x00000000" ascii //weight: 2
        $x_1_5 = "If this is the first time you`ve seen this Stop error screen, restart you" ascii //weight: 1
        $x_1_6 = "new installation, ask you software manufacturer for any antivirus updates" ascii //weight: 1
        $x_1_7 = "Windows detected unregistred version of Antivirus 2010 protection on your computer." ascii //weight: 1
        $x_1_8 = "If problem continue, please activate your antivirus software to prevent compter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{3C40236D-990B-443C-90E8-B1C07BCD4A68}" wide //weight: 2
        $x_2_2 = "av2010.net" wide //weight: 2
        $x_2_3 = "Software\\AV2010\\AV2010\\{F275E931-AFEC-4f70-B0D4-CC2731B945E0}" wide //weight: 2
        $x_1_4 = "http://microsoft.browser-security-center.com/blocked.php?id=" wide //weight: 1
        $x_1_5 = "review.2009softwarereviews.com" wide //weight: 1
        $x_1_6 = "reviews.techradar.com" wide //weight: 1
        $x_1_7 = "reviews.riverstreams.co.uk" wide //weight: 1
        $x_1_8 = "reviews.reevoo.com" wide //weight: 1
        $x_1_9 = "reviews.pcpro.co.uk" wide //weight: 1
        $x_1_10 = "reviews.pcmag.com" wide //weight: 1
        $x_1_11 = "reviews.pcadvisor.co.uk" wide //weight: 1
        $x_1_12 = "reviews.download.com" wide //weight: 1
        $x_1_13 = "reviews.toptenreviews.com" wide //weight: 1
        $x_1_14 = "d1.reviews.cnet.com" wide //weight: 1
        $x_1_15 = "a1.review.zdnet.com" wide //weight: 1
        $x_1_16 = "microsoft.browser-security-center.com" wide //weight: 1
        $x_1_17 = "plimus.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Antivirus 2010" wide //weight: 2
        $x_2_2 = "?step=av2010_complete&id=" wide //weight: 2
        $x_2_3 = "/activate.php?email=" wide //weight: 2
        $x_2_4 = "c:\\users\\serhij\\documents\\visual studio 2008\\projects\\" wide //weight: 2
        $x_1_5 = "Function Update is diabled. Critical threat of being attacked by novel viruses and spyware." wide //weight: 1
        $x_1_6 = "In case automatic updating is not performed, your PC is under threat of being attacked by novel" wide //weight: 1
        $x_1_7 = "This function allows the program to perform automatic updating to raise your system security" wide //weight: 1
        $x_1_8 = "detected internal software conflict. Some applicztion tries to get access to system kernel" wide //weight: 1
        $x_1_9 = "protection has detected Spyware program Win32.Monster.fx that is trying to attack your" wide //weight: 1
        $x_1_10 = "detected a Privacy Violation. A program is secretly sending your private data to an untrusted" wide //weight: 1
        $x_1_11 = "Some critical system files of your computer were modified by malicious program" wide //weight: 1
        $x_1_12 = "Spyware.IEMonster activity detected. It is spyware that attempts to steal passwords" wide //weight: 1
        $x_1_13 = "Security center reports that 'Antivirus 2010' is inactive. Antivirus software helps to protect" wide //weight: 1
        $x_1_14 = "ERROR. E-mail you entered is not registered in our transaction database.It seems that purchase" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6f 74 6f 48 65 6c 6c 31 32 33 31 32 33 5f 5f 00 00 00 00 53 68 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00 ?? ?? ?? ?? 55 6e 69 6e 73 74 61 6c 6c 00 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 6e 2e 63 66 67 00 20 75 70 64 61 74 65}  //weight: 2, accuracy: High
        $x_1_2 = {73 70 79 77 61 72 65 2e 64 61 74 00 73 70 79 77 61 72 65 2e 6f 6c 64}  //weight: 1, accuracy: High
        $x_1_3 = "Database is up-to-date!" ascii //weight: 1
        $x_1_4 = {76 65 72 2e 74 78 74 [0-4] 76 65 72 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {73 70 79 77 61 72 65 2e 74 6d 70 00 61 75 74 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 51 12 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3 05 00 ff ?? ?? 81}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 f4 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3 07 00 ff ?? ?? 81 ?? 90 90}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 00 81 f8 83 fa 08 0f 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 44 65 66 65 6e 63 65 20 43 65 6e 74 65 31 2e ?? 2e ?? 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 75 73 74 6f 6d 00 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 63 65 20 01 00 2e 01 00 2e 01 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 15 6a 2c 68 ?? ?? ?? ?? 68 c2 01 00 00 6a 10 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "Physical memory dump complete. Restarting..." ascii //weight: 1
        $x_1_3 = "*** DRV.SYS - Address" ascii //weight: 1
        $x_1_4 = "BlueScreen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 64 6c 6c 2e 64 6c 6c 00 6d 79 46 75 6e 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_2_3 = {68 ff 07 00 00 be ?? ?? 00 10 56 ff 35 ?? ?? 00 10 ff 15}  //weight: 2, accuracy: Low
        $x_3_4 = {6a 22 83 c0 1a 68 ?? ?? 00 10 68 ?? ?? 00 10 a3 ?? ?? 00 10 e8}  //weight: 3, accuracy: Low
        $x_1_5 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 [0-8] 2e 00 63 00 6f 00 6d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_27
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {75 68 c6 45 e7 01 33 f6 8b 45 e8 8d 58 3c 8d 45 cc 50 8b 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 49}  //weight: 4, accuracy: Low
        $x_2_2 = {5b 46 4c 54 5d 00 00 00 ff ff ff ff 05 00 00 00 5b 50 4f 50 5d 00}  //weight: 2, accuracy: High
        $x_2_3 = {5b 6b 65 79 5d 00 00 00 03 00 00 00 ff ff ff ff 06 00 00 00 3f 6e 69 63 6b 3d 00}  //weight: 2, accuracy: High
        $x_2_4 = "[SRV];(?i)" ascii //weight: 2
        $x_2_5 = {5b 53 52 56 5d 00 00 00 ff ff ff ff 03 00 00 00 23 23 23 00}  //weight: 2, accuracy: High
        $x_1_6 = "/buy.php?id=%aff%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_28
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\Earth\\\\{A57287DA-6FB8-7CA8-7B68-768BD76FD4FD}" ascii //weight: 1
        $x_1_2 = {5c 45 61 72 74 68 20 41 56 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Programs\\Earth AV" ascii //weight: 1
        $x_1_4 = " /im McNASvc.exe " ascii //weight: 1
        $x_1_5 = {5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 2a 2e 2a 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 65 63 61 5c 65 72 61 70 70 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_29
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_2 = {00 00 53 6f 66 74 77 61 72 65 5c 58 50 20 41 6e 74 69 76 69 72 75 73 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 58 50 20 41 6e 74 69 76 69 72 75 73 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {58 50 20 41 6e 74 69 76 69 72 75 73 [0-6] 75 6e 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79}  //weight: 1, accuracy: Low
        $x_1_5 = "TfrmXPAMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_30
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smservice_start_gui_event" wide //weight: 1
        $x_1_2 = "Control\\DefenceCenter\\Info" wide //weight: 1
        $x_1_3 = "smmservice_with_regedit\\Release\\smmservice.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_31
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 09 8b 15 ?? ?? 40 00 2b d0 33 c9 8b 07 e8 ?? ?? ff ff 8d 55 fc b9 04 00 00 00 8b 07 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_2_2 = {7e 29 8d 55 ef b9 01 00 00 00 8b 07 e8 ?? ?? ff ff a0 ?? ?? 40 00 30 45 ef 8d 55 ef b9 01 00 00 00 8b c6 e8 ?? ?? ff ff 4b 75 d7}  //weight: 2, accuracy: Low
        $x_1_3 = {83 e8 3a c1 e0 06 [0-16] e9 ?? 00 00 00 [0-16] 83 e8 3a c1 e0 0c [0-16] (eb|e9) [0-16] 83 e8 3a c1 e0 12}  //weight: 1, accuracy: Low
        $x_1_4 = "XPantivirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_32
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 70 79 77 61 72 65 00 52 69 73 6b 77 61 72 65 00 50 61 63 6b 65 64 2c 20 70 6f 73 73 69 62 6c 65 20 73 70 79 77 61 72 65}  //weight: 10, accuracy: High
        $x_10_2 = "Microsoft Win32s ;)" ascii //weight: 10
        $x_10_3 = {00 53 53 53 2e 73 79 73 00}  //weight: 10, accuracy: High
        $x_5_4 = {55 70 64 61 74 65 2e 65 78 65 00 6f 70 65 6e 00 75 70 64 61 74 65 2e 65 78 65}  //weight: 5, accuracy: High
        $x_5_5 = {53 68 65 6c 6c 00 72 75 6e 20 26 20 6c 6f 61 64}  //weight: 5, accuracy: High
        $x_5_6 = {00 55 73 65 72 49 6e 69 74 20 68 69 6a 61 63 6b 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 76 65 72 2e 64 61 74 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_33
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 73 63 75 69 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 10, accuracy: High
        $x_10_2 = {43 61 70 74 69 6f 6e [0-2] 57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72}  //weight: 10, accuracy: Low
        $x_10_3 = "AppletIcon.Data" ascii //weight: 10
        $x_10_4 = "AppletModuleActivate" ascii //weight: 10
        $x_1_5 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_6 = "GetStartupInfoA" ascii //weight: 1
        $x_1_7 = "CreateBitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_34
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 62 6c 6b 63 6f 64 65 25 00}  //weight: 2, accuracy: High
        $x_2_2 = {41 66 66 49 44 00 00 00 ff ff ff ff 05 00 00 00 25 61 66 66 25 00}  //weight: 2, accuracy: High
        $x_1_3 = {70 72 74 6b 3a 3a 62 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "<title>Blocked</title>" ascii //weight: 1
        $x_3_5 = ".php?af=%aff%&url=%url% frameborder=0" ascii //weight: 3
        $x_2_6 = {41 66 66 49 44 00 00 00 ff ff ff ff 09 00 00 00 41 63 74 69 76 61 74 65 64 00}  //weight: 2, accuracy: High
        $x_1_7 = "_IEBrowserHelper.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_35
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6e 73 45 78 65 63 2e 64 6c 6c 00 ?? ?? 2e 65 78 65 20 2d 70 61 73 73 77 6f 72 64 3d [0-16] 00 45}  //weight: 2, accuracy: Low
        $x_1_2 = {00 50 50 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 61 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {20 41 6e 74 69 56 69 72 75 73 20 0a 00 01 00 2e 01 00 2e 01 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_2_5 = {45 41 56 20 0a 00 01 00 2e 01 00 2e 01 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_1_6 = {00 65 72 2e 65 78 65 00 6d 73 77 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_36
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 02 ff 21 75 1a 8b 45 fc e8 ?? ?? ff ff 8b d0 8d 45 fc b9 01 00 00 00 e8 ?? ?? ff ff ff 45 e8 4b 75 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e2 3f 8b cf c1 e1 03 8d 0c cd ?? ?? ?? ?? 0f b6 14 11 8b 4d ec 83 e1 c0 0b d1 e8 ?? ?? ff ff 8b 55 e0 8b 45 f8 e8 ?? ?? ff ff 8b 45 f8 83 ff 0f 75 04 33 ff eb 01 47 c1 ee 08 ff 4d f4 75 b0}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 83 8c 05 00 00 e8 ?? ?? ff ff 8b 4b 28 e3 10 ff b3 8c 05 00 00 6a 00 6a 0c 51 e8 ?? ?? ff ff 0f b6 8b c2 00 00 00 e2 07 89 d8 e8 ?? ?? 00 00 93 5b ff b0 00 01 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_37
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 00 69 00 6e 00 64 00 56 00 69 00 65 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 74 00 68 00 69 00 73 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 61 00 6e 00 79 00 77 00 61 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 00 43 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 20 00 41 00 6e 00 79 00 77 00 61 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_4_4 = {be 01 00 01 00 56 6a 01 68 01 02 00 00 ff b5 ?? ?? ff ff ff d7 56 6a 01 68 02 02 00 00 ff b5 ?? ?? ff ff e9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_38
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 64 64 53 65 65 73 69 6f 6e 53 51 4e 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 45 57 20 44 45 53 54 3a 20 25 30 75 2e 25 30 75 2e 25 30 75 2e 25 30 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 45 54 20 2f 73 65 61 72 63 68 3f 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 45 54 20 2f 73 65 61 72 63 68 3b 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 45 54 20 2f 72 65 73 75 6c 74 73 2e 61 73 70 78 3f 00}  //weight: 1, accuracy: High
        $x_4_6 = {61 6e 74 69 76 69 72 79 73 00 61 6e 74 69 76 79 72 75 73 00 61 6e 74 79 76 69 72 75 73 00 61 6e 74 69 76 69 72 75 73 00}  //weight: 4, accuracy: High
        $x_4_7 = {68 61 50 6d 49 6a 2e 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 6a 2e ff 75 ?? 8d 45 ?? ff b3 f4 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_39
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 78 70 61 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "XPA\\LOADER\\MAINICON" ascii //weight: 1
        $x_1_3 = "and install XP antivirus" ascii //weight: 1
        $x_1_4 = "xpantivirus.com/eula" ascii //weight: 1
        $x_1_5 = {64 6f 77 6e 6c 6f 61 64 2f 78 70 61 [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 58 50 20 41 6e 74 69 76 69 72 75 73}  //weight: 1, accuracy: High
        $x_1_7 = "Uninstall XP An" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_40
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 41 6e 74 69 56 69 72 75 73 20 49 6e 73 74 61 6c 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d 61 6e 74 69 76 69 72 75 73 2d 32 30 02 00 2e 63 6f 6d 2f 74 65 72 6d 73 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {54 6f 20 63 6f 6e 74 69 6e 75 65 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 63 6c 6f 73 65 20 61 6c 6c 20 [0-12] 49 6e 74 65 72 6e 65 74 20 42 72 6f 77 73 65 72 73 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {00 42 61 73 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 68 69 73 20 77 69 6c 6c 20 69 6e 73 74 61 6c 6c 20 [0-8] 20 41 56 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_41
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Your system might be at risk!" ascii //weight: 2
        $x_2_2 = "Install free XP antivirus scanner now!" ascii //weight: 2
        $x_2_3 = "- Free handy Virus Statistics" ascii //weight: 2
        $x_3_4 = {83 e8 3a c1 e0 06 [0-16] e9 ?? 00 00 00 [0-16] 83 e8 3a c1 e0 0c [0-16] (eb|e9) [0-16] 83 e8 3a c1 e0 12}  //weight: 3, accuracy: Low
        $x_3_5 = {8d 83 8c 05 00 00 e8 ?? ?? ff ff 8b 4b 28 e3 10 ff b3 8c 05 00 00 6a 00 6a 0c 51 e8 ?? ?? ff ff 0f b6 8b c2 00 00 00 e2 07 89 d8 e8 ?? ?? 00 00 93 5b ff b0 00 01 00 00 c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_42
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Locales" ascii //weight: 10
        $x_1_2 = "confirm.php?product=%product%&aff=%aff%&email=%email%" ascii //weight: 1
        $x_1_3 = ".php?ver=%aff%" ascii //weight: 1
        $x_1_4 = ".dll###Dialer." ascii //weight: 1
        $x_1_5 = ".exe###Win32.Rbot." ascii //weight: 1
        $x_1_6 = "autorun###Win32." ascii //weight: 1
        $x_1_7 = {44 65 66 20 74 72 65 61 74 73 3a 20 00}  //weight: 1, accuracy: High
        $x_1_8 = {41 66 74 65 72 20 72 65 67 69 73 74 65 72 20 55 52 4c 3a 20 00}  //weight: 1, accuracy: High
        $x_2_9 = {53 63 61 6e 20 4e 6f 77 00 00 00 00 ff ff ff ff 04 00 00 00 53 74 6f 70 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_43
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 98 3a 00 00 6a 0a 56 89 0d ?? ?? ?? ?? ff d7 6a 00 68 20 4e 00 00 6a 0b 56 ff d7 6a 00 68 30 75 00 00 6a 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 00 ad 00 56 ff 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 74 15 6a ?? 68 ?? ?? ?? ?? 68 c2 01 00 00 6a ?? 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 0b 75 ?? 68 fa 00 00 00 68 c2 01 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 20 00 [0-4] 6d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 [0-4] 64 00 75 00 6d 00 70 00 20 00 [0-4] 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 2e 00 20 00 [0-4] 52 00 65 00 73 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 [0-4] 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_44
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 3f 71 3d 00 26 71 3d 00 3f 70 3d 00 26 70 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 57 79 00 00 56 79 00 00 77 79 00 00 76 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 6f 66 74 77 61 72 65 5c ?? 41 56 5c ?? 41 56}  //weight: 1, accuracy: Low
        $x_1_4 = {00 57 69 00 00 56 69 00 00 77 69 00 00 76 69 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 41 6e 74 79 00 00 00 00 61 6e 74 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 72 63 3d 68 74 74 70 3a 2f 2f 6d 69 63 72 6f 73 6f 66 74 01 00 2e 20 00 2e 04 00 2f}  //weight: 1, accuracy: Low
        $x_1_7 = "trynewsecurity.info" ascii //weight: 1
        $x_1_8 = "d:\\!!!WORK\\awork\\soft\\soft\\" ascii //weight: 1
        $x_1_9 = "Reported Attack Site!</title>" ascii //weight: 1
        $x_1_10 = "mit\" value=\"Get me our of here" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_45
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 74 00 5f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 74 00 79 00 70 00 65 00 3d 00 73 00 69 00 74 00 65 00 00 00 41 00 56 00 31 00 39 00 5f 00 47 00 65 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\AV1\\AV1\\{F275E931-AFEC-" wide //weight: 1
        $x_1_3 = {65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 73 00 74 00 65 00 70 00 3d 00 00 00 00 00 26 00 69 00 64 00 3d 00 00 00 00 00 6e 00 6f 00 6e 00 65 00 00 00 00 00 73 70 65 63 69 61 6c 69 6e 66 6f 3a 69 64 3d 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\AVInstaller_2\\Release\\Stage" ascii //weight: 1
        $x_5_5 = {8b 2d 70 91 40 00 8b 44 24 18 85 c0 74 3c 50 e8 ?? ?? ?? ?? 83 c4 04 8b f8 8b 44 24 18 8d 54 24 20 52 50 57 56 ff d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_46
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 6f 61 64 46 69 72 65 77 61 6c 6c 52 75 6c 65 73 28 29 00 66 69 72 65 77 61 6c 6c 2e 63 66 67 00 66 69 72 65 77 61 6c 6c 2e 63 66 67 00 4c 6f 61 64 57 68 69 74 65 4c 69 73 74 28 29 00 77 68 69 74 65 6c 69 73 74 2e 63 66 67 00 77 68 69 74 65 6c 69 73 74 2e 63 66 67 00 4c 6f 61 64 69 6e 67 20 64 61 74 61 62 61 73 65 2e 2e 2e 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 70 79 77 61 72 65 00 52 69 73 6b 77 61 72 65 00 50 61 63 6b 65 64 2c 20 70 6f 73 73 69 62 6c 65 20 73 70 79 77 61 72 65 00}  //weight: 10, accuracy: High
        $x_5_3 = {00 76 65 72 2e 64 61 74 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 55 73 65 72 49 6e 69 74 20 68 69 6a 61 63 6b 00}  //weight: 5, accuracy: High
        $x_5_5 = {53 79 73 42 61 63 6b 75 70 5c 00 2e 6d 64 35 00}  //weight: 5, accuracy: High
        $x_1_6 = {11 69 6d 67 53 74 61 72 74 53 63 61 6e 43 6c 69 63 6b}  //weight: 1, accuracy: High
        $x_1_7 = {54 53 70 79 77 61 72 65 46 6f 75 6e 64 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $n_20_8 = "XenAntiSpyware_running" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_47
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\Eco\\\\{A57287DA-6FB8-7CA8-7B68-768BD76FD4FD}" ascii //weight: 10
        $x_10_2 = {5c 50 72 6f 67 72 61 6d 73 5c [0-2] 45 63 6f [0-2] 41 6e 74 69 56 69 72 75 73 [0-2] 5c [0-2] 45 63 6f [0-2] 41 6e 74 69 56 69 72 75 73 [0-2] 2e 6c 6e 6b}  //weight: 10, accuracy: Low
        $x_1_3 = "taskkill /f /im ecoav.exe" ascii //weight: 1
        $x_1_4 = "taskkill /f /im MSASCui.exe" ascii //weight: 1
        $x_1_5 = "taskkill /f /im nod32krn.exe" ascii //weight: 1
        $x_1_6 = "taskkill /f /im mcregist.exe " ascii //weight: 1
        $x_1_7 = "/im wmiprvse.exe " ascii //weight: 1
        $x_1_8 = "/im mcsysmon.exe " ascii //weight: 1
        $x_1_9 = "/im Mcshield.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_48
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWProtect" ascii //weight: 1
        $x_1_2 = "trynewsecurity.info" wide //weight: 1
        $x_1_3 = {44 6c 6c 49 6e 73 74 61 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "{29256442-2C14-48CA-B756-3EE0F8BDC774}" wide //weight: 1
        $x_1_5 = "Software\\Eco\\Eco\\" wide //weight: 1
        $x_1_6 = "Software\\Earth\\Earth\\" wide //weight: 1
        $x_1_7 = "\">Online phishing (pronounced fishing) is a way to trick y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeXPA_18119_49
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/admin/cgi-bin/get_domain.php?type=" ascii //weight: 3
        $x_2_2 = "Click \"Next\" to proceed with AntiVirus installation" ascii //weight: 2
        $x_2_3 = "collection.php?step=" ascii //weight: 2
        $x_1_4 = {41 56 42 48 4f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 56 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "Software\\Antivirus AV" ascii //weight: 1
        $x_1_7 = "Spyware.IEMonster activity detected." ascii //weight: 1
        $x_1_8 = "/blocked.php?id=" ascii //weight: 1
        $x_1_9 = "/presale/2/index.php?id=" ascii //weight: 1
        $x_1_10 = "free+antivirus+software" ascii //weight: 1
        $x_1_11 = "/blocked.php?id=" wide //weight: 1
        $x_1_12 = "antivirys" wide //weight: 1
        $x_1_13 = "anti+vitys" wide //weight: 1
        $x_1_14 = "anti-vitus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_50
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 80 01 00 00 8d 44 24 ?? 50 ff d6 8b f8 83 ff ff 74 2c 53 8d 44 24 ?? 50 6a 60 8d 44 24 ?? 50 53 53 68 64 00 09 00 57 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b7 48 04 33 d2 42 56 8b f2 03 c8 66 3b 70 06 73 1e 8d b0 fe 01 00 00 57 66 8b 3c 51 66 89 3e 0f b7 78 06 81 c6 00 02 00 00 42 3b d7 72 ea}  //weight: 2, accuracy: High
        $x_2_3 = {0f b7 41 14 03 c1 eb 0f 3b 4c 24 04 75 06 80 78 09 00 74 0c 03 40 04 8b 08 83 f9 ff 75 ea}  //weight: 2, accuracy: High
        $x_1_4 = "RE\\KasperskyLab\\SetupFolders\\" wide //weight: 1
        $x_1_5 = "Identity Protection\\Agent\\Bin\\AVGIDSAgent.exe" wide //weight: 1
        $x_1_6 = "RE\\Norton\\{0C55C096-0F" wide //weight: 1
        $x_1_7 = "RE\\McAfee\\SiteAdv" wide //weight: 1
        $x_1_8 = "RE\\AVAST Software\\Avast" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_51
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 ff 07 00 00 8d 44 24 1c 50 55 ff 15 ?? ?? ?? ?? 85 c0 74 60 8b 4c 24 0c 33 c0 85 c9 76 11 80 7c 04 10 00 75 05 c6 44 04 10 2d 40 3b c1 72 ef}  //weight: 5, accuracy: Low
        $x_2_2 = "/admin/cgi-bin/get_domain.php?type=" wide //weight: 2
        $x_2_3 = "collection.php?step=" wide //weight: 2
        $x_1_4 = "_GetId_failure" wide //weight: 1
        $x_1_5 = "_install_run" wide //weight: 1
        $x_1_6 = "_inst_dl_failure" wide //weight: 1
        $x_1_7 = "_inst_run_failure" wide //weight: 1
        $x_1_8 = "_stage_one_complete" wide //weight: 1
        $x_1_9 = "_install_run_autostart" wide //weight: 1
        $x_1_10 = "_hosts_patch_failure" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_52
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2f 00 61 00 64 00 6d 00 69 00 6e 00 2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 2f 00 67 00 65 00 74 00 5f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00 70 00 68 00 70 00 [0-8] 74 00 79 00 70 00 65 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 [0-8] 47 00 45 00 54 00}  //weight: 3, accuracy: Low
        $x_1_2 = "You need to have internet access to download and install the free version of AntivirusBEST." wide //weight: 1
        $x_1_3 = "Software\\ABEST\\ABEST\\{C9DB4911-745E-4420-ADE0-FAA5E2A24E8C}" wide //weight: 1
        $x_1_4 = {63 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 [0-10] 73 00 74 00 65 00 70 00 3d 00 [0-10] 26 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Local\\AntivirusBEST" wide //weight: 1
        $x_1_6 = "70.38.11.165" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_53
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 41 6e 74 69 76 69 72 75 73 20 32 30 ?? ?? 20 77 69 6c 6c 20 62 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 65 64 20 6e 6f 77}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 00 41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}  //weight: 2, accuracy: High
        $x_2_3 = "regsvr32 /s QWProtect.dll" ascii //weight: 2
        $x_2_4 = {74 6f 70 74 65 6e 72 65 76 69 65 77 73 2e 63 6f 6d 0d 0a 00 03 00 2e 03 00 2e 03 00 2e 03 00 04 00 77 77 77 2e 72 65 65 76 6f 6f 2e 63 6f 6d}  //weight: 2, accuracy: Low
        $x_2_5 = {65 78 64 6c 6c 2e 64 6c 6c 00 6d 79 46 75 6e 63 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_1_6 = "taskkill /f /im MSASCui.exe" ascii //weight: 1
        $x_1_7 = "taskkill /f /im mcregist.exe /im" ascii //weight: 1
        $x_1_8 = "taskkill /f /im nod32krn.exe" ascii //weight: 1
        $x_2_9 = {67 61 76 5f 69 6e 73 74 61 6c 6c 5f 69 65 70 6c 75 67 69 6e 00}  //weight: 2, accuracy: High
        $x_1_10 = {5c 56 69 72 75 73 65 73 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {53 65 6c 66 44 65 6c 2e 64 6c 6c 00 64 65 6c 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 67 61 76 5f}  //weight: 1, accuracy: High
        $x_2_13 = {20 41 6e 74 69 56 69 72 75 73 20 01 00 2e 01 00 2e 01 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_1_14 = {55 41 43 2e 64 6c 6c 00 52 75 6e 45 6c 65 76 61 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_15 = {5c 77 65 72 74 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_16 = {00 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 45 78 65 63 00 72 65 67 73 76 72 33 32 20 2f 73 20 57 53 74 65 63 68 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_17 = {20 41 6e 74 69 56 69 72 75 73 20 0a 00 01 00 2e 01 00 2e 01 00 0a 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_1_18 = "-av.com" ascii //weight: 1
        $x_1_19 = "#\\Microsoft\\Machine\\WStech.dll" ascii //weight: 1
        $x_2_20 = {45 41 56 20 0a 00 01 00 2e 01 00 2e 01 00 0a 00 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: Low
        $x_2_21 = {72 65 67 73 76 72 33 32 20 2f 73 20 77 73 63 72 2e 64 6c 6c 00 45 78 65 63 00 [0-6] 5c 65 78 74 65 6e 73 69 6f 6e 73 5c 67 73 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_54
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Antivirus 2010 system scan report." wide //weight: 1
        $x_1_2 = "/av2010/version.php" wide //weight: 1
        $x_1_3 = "/av2010/updater.exe" wide //weight: 1
        $x_1_4 = "{3539DFE8-6BE9-44a3-8E78-44DBAE5BDC13}" wide //weight: 1
        $x_1_5 = "?step=av2010_complete" wide //weight: 1
        $x_1_6 = {2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 61 64 6d 69 6e 2f 63 67 69 2d 62 69 6e 2f 67 65 74 5f 64 6f 6d 61 69 6e 2e 70 68 70 3f 74 79 70 65 3d 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 61 64 6d 69 6e 2f 63 67 69 2d 62 69 6e 2f 67 65 74 5f 64 6f 6d 61 69 6e 2e 70 68 70 3f 74 79 70 65 3d 73 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {2f 63 6f 6c 6c 65 63 74 69 6f 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_10 = "has automatically updated the virus database. Now your computer is protected" ascii //weight: 1
        $x_1_11 = "?step=N19_complete_8&id=" ascii //weight: 1
        $x_1_12 = "{84283E6B-C377-498f-BF91-698E877555CC}" wide //weight: 1
        $x_1_13 = "{F275E931-AFEC-4f70-B0D4-CC2731B945E0}" wide //weight: 1
        $x_4_14 = {6a 01 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? eb ?? 8b f4 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 (45 ??|85 ?? ?? ?? ??) 83 (7d ??|bd ?? ?? ?? ??) 00 74 ?? 8b f4 68 03 02 00 00 6a 00 68 7b 80 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_55
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 00 50 00 59 00 57 00 41 00 52 00 45 00 2e 00 4d 00 4f 00 4e 00 53 00 54 00 45 00 52 00 2e 00 46 00 58 00 5f 00 57 00 49 00 4c 00 44 00 5f 00 30 00 78 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "Windows detected unregistred version of Antivirus 2010 protection on your computer" wide //weight: 10
        $x_10_3 = {2a 00 2a 00 2a 00 20 00 53 00 52 00 56 00 2e 00 53 00 59 00 53 00 20 00 2d 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 46 00 37 00 33 00 31 00 32 00 30 00 41 00 45 00 20 00 62 00 61 00 73 00 65 00 20 00 61 00 74 00 20 00 43 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 2c 00 20 00 44 00 61 00 74 00 65 00 53 00 74 00 61 00 6d 00 70 00 20 00 33 00 36 00 62 00 30 00 37 00 32 00 61 00 33 00 00 00}  //weight: 10, accuracy: High
        $x_5_4 = {2a 00 2a 00 2a 00 53 00 54 00 4f 00 50 00 3a 00 20 00 30 00 78 00 30 00 30 00 30 00 30 00 30 00 30 00 44 00 31 00 20 00 28 00 30 00 78 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 2c 00 20 00 30 00 78 00 46 00 37 00 33 00 31 00 32 00 30 00 41 00 45 00 2c 00 20 00 30 00 78 00 43 00 30 00 30 00 30 00 30 00 30 00 30 00 38 00 2c 00 20 00 30 00 78 00 43 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 29 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = "A spyware application has been detected and Windows has been shut down to" wide //weight: 5
        $x_15_6 = {68 00 00 ad 00 56 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 6a 44 68 ?? ?? ?? ?? 6a 14 6a 10 56 ff d7 6a 49 68 ?? ?? ?? ?? 6a 3c 6a 10 56 ff d7}  //weight: 15, accuracy: Low
        $x_15_7 = {68 ff ff ff 00 56 ff 15 ?? ?? ?? ?? 68 00 00 ad 00 56 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 68 00 01 00 00 8d 44 24 ?? 50 6a 68 51 ff}  //weight: 15, accuracy: Low
        $x_10_8 = {6a 00 68 98 3a 00 00 6a 6e 56 ff d7 6a 00 68 20 4e 00 00 6a 6f 56 ff d7 6a 00 68 30 75 00 00 6a 70}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*))) or
            ((2 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_56
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 00 6e 00 74 00 69 00 2d 00 56 00 69 00 72 00 75 00 73 00 20 00 4e 00 75 00 6d 00 62 00 65 00 72 00 2d 00 31 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {45 00 6e 00 61 00 62 00 6c 00 65 00 20 00 61 00 6e 00 74 00 69 00 72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {20 00 2d 00 20 00 54 00 68 00 72 00 65 00 61 00 74 00 73 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 50 00 43 00 20 00 66 00 72 00 6f 00 6d 00 20 00 76 00 69 00 6f 00 6c 00 65 00 6e 00 74 00 20 00 76 00 69 00 72 00 75 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Spyware C://windows/system32/iesetup.dll" wide //weight: 1
        $x_1_6 = "Trojan.Tooso" wide //weight: 1
        $x_1_7 = {43 00 68 00 65 00 63 00 6b 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 61 00 72 00 65 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_8 = {20 00 70 00 72 00 69 00 76 00 69 00 74 00 65 00 [0-10] 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 [0-10] 6d 00 6f 00 72 00 65 00 [0-10] 76 00 75 00 6c 00 6e 00 65 00 72 00 61 00 62 00 6c 00 65 00}  //weight: 2, accuracy: Low
        $x_2_9 = "detected internal software conflict. Some applicztion tries" wide //weight: 2
        $x_1_10 = "QWProtect.dll" wide //weight: 1
        $x_2_11 = "MaCatte " wide //weight: 2
        $x_2_12 = {20 70 72 69 76 69 74 65 [0-10] 69 6e 66 6f 72 6d 61 74 69 6f 6e [0-10] 6d 6f 72 65 [0-10] 76 75 6c 6e 65 72 61 62 6c 65}  //weight: 2, accuracy: Low
        $x_1_13 = "taskkill.exe /f /im MSASCui.exe" ascii //weight: 1
        $x_1_14 = "d:\\!!!WORK\\awork\\soft\\soft\\" ascii //weight: 1
        $x_1_15 = {6d 00 61 00 6c 00 63 00 6f 00 75 00 73 00 20 00 [0-10] 54 00 72 00 6f 00 6a 00 61 00 6e 00 73 00}  //weight: 1, accuracy: Low
        $x_1_16 = "Earth AntiVirus" ascii //weight: 1
        $x_1_17 = "Software\\GAV\\GAV\\" wide //weight: 1
        $x_1_18 = "DefenceCenter Antivirus" wide //weight: 1
        $x_1_19 = "Setup.InDepthAnalisis" ascii //weight: 1
        $x_1_20 = "Update.AutoUpdateProgrammNotifyWhenDone" ascii //weight: 1
        $x_1_21 = "WIN.RGXP.Tooso" wide //weight: 1
        $x_1_22 = "DefenceCenterViewMessagesCatcherWindow" wide //weight: 1
        $x_1_23 = "DefenceModelMessagesCatcherWindow" wide //weight: 1
        $x_1_24 = {41 56 44 42 50 61 74 68 20 3d 20 22 43 3a 5c 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 5c 41 6c 6c 20 55 73 65 72 73 5c 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 5c [0-10] 5c 5c 64 62 2e 61 76 64 62 22}  //weight: 1, accuracy: Low
        $x_1_25 = "Windows_Defence_Project" wide //weight: 1
        $x_1_26 = "_Security_Center_Project" wide //weight: 1
        $x_1_27 = "Setup.InspectHiddenProccesses" ascii //weight: 1
        $x_1_28 = "Software\\Defence\\Config" wide //weight: 1
        $x_1_29 = "Software\\Dfc\\Config" ascii //weight: 1
        $x_1_30 = "Setup.AntiRootkit" ascii //weight: 1
        $x_1_31 = "Info.SecCenterExeName" ascii //weight: 1
        $x_1_32 = "ows Defence reports that it" wide //weight: 1
        $x_1_33 = "ion Data\\Dfc\\Config" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeXPA_18119_57
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeXPA"
        threat_id = "18119"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeXPA"
        severity = "142"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 55 52 4c 00 00 00 00 ff ff ff ff 04 00 00 00 44 41 46 46 00 00 00 00 ff ff ff ff 04 00 00 00 54 52 4d 53 00 00 00 00 ff ff ff ff 05 00 00 00 46 42 55 52 4c 00}  //weight: 2, accuracy: High
        $x_2_2 = "Security Violation Error###Internet Explorers addon Shockwave Flash vs.3" ascii //weight: 2
        $x_1_3 = {46 41 56 47 00 00 00 00 ff ff ff ff 05 00 00 00 41 66 66 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 41 56 47 00 00 00 00 ff ff ff ff 07 00 00 00 5b 44 4f 4d 41 49 4e 00}  //weight: 1, accuracy: High
        $x_1_5 = "/buy.php?id=%affid%" ascii //weight: 1
        $x_1_6 = "/?act=vv&id=%affid%" ascii //weight: 1
        $x_1_7 = "/?act=reg&type=%productid%&id=%affid%" ascii //weight: 1
        $x_1_8 = {25 62 72 6f 77 73 65 72 25 00 00 00 ff ff ff ff 05 00 00 00 41 66 66 49 44 00 00 00 ff ff ff ff 07 00 00 00 25 61 66 66 69 64 25 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 63 74 69 76 61 74 69 6f 6e 54 79 70 65 00 00 ff ff ff ff 09 00 00 00 25 61 63 74 74 79 70 65 25 00}  //weight: 1, accuracy: High
        $x_1_10 = {44 41 46 46 00 00 00 00 ff ff ff ff 06 00 00 00 48 4c 50 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_11 = {78 78 78 50 41 56 4d 54 58 00}  //weight: 1, accuracy: High
        $x_1_12 = {53 65 74 75 70 20 2d 20 50 41 56 00}  //weight: 1, accuracy: High
        $x_1_13 = "It is recommended that you close all other applications and antiviruses before continuing." ascii //weight: 1
        $x_1_14 = {25 76 6d 64 65 74 65 63 74 25 00 00 ff ff ff ff 0c 00 00 00 25 77 69 6e 69 6e 73 74 61 6c 6c 25 00}  //weight: 1, accuracy: High
        $x_1_15 = {74 73 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_16 = "smss.exe||csrss.exe||winlogon.exe" ascii //weight: 1
        $x_1_17 = {8b 45 fc 0f b6 44 18 ff 83 e8 3a c1 e0 06 0b f0}  //weight: 1, accuracy: High
        $x_1_18 = {53 63 61 6e 20 4e 6f 77 00 00 00 00 ff ff ff ff 04 00 00 00 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_19 = "Spyware.IEMonster activity detected." ascii //weight: 1
        $x_1_20 = {41 66 66 49 44 00 00 00 4c 64 72 55 53 41 00}  //weight: 1, accuracy: High
        $x_1_21 = {42 79 20 63 6c 69 63 6b 69 6e 67 20 43 6f 6e 74 69 6e 75 65 20 62 75 74 74 6f 6e 20 79 6f 75 (20 61 72|20) 61 63 63 65 70 74 69 6e 67 20 6f 75 72}  //weight: 1, accuracy: Low
        $x_1_22 = {66 72 6d 55 53 41 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_23 = {25 76 6d 64 65 74 65 63 74 25 00 00 ff ff ff ff 08 00 00 00 25 62 61 64 75 72 6c 25}  //weight: 1, accuracy: High
        $x_1_24 = "TpavMainForm" ascii //weight: 1
        $x_1_25 = {54 66 6d 41 56 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_26 = {45 56 41 53 6d 61 6c 6c 43 6f 6d 70 6f 6e 65 6e 74 73 00}  //weight: 1, accuracy: High
        $x_1_27 = {45 56 41 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_28 = {53 6f 66 74 77 61 72 65 5c 45 56 41 46 46 46 5c 00}  //weight: 1, accuracy: High
        $x_1_29 = {2f 64 6f 77 6e 6c 6f 61 64 2f 65 76 61 2e 64 72 76 00}  //weight: 1, accuracy: High
        $x_1_30 = {45 56 41 47 6c 6f 62 61 6c 73 00}  //weight: 1, accuracy: High
        $x_1_31 = {74 61 62 41 6e 74 69 53 70 79 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_32 = {74 61 62 52 65 73 53 68 69 65 6c 64 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_33 = {5b 44 4f 4d 41 49 4e 00 ff ff ff ff 01 00 00 00 5d 00}  //weight: 1, accuracy: High
        $x_1_34 = {41 66 66 49 44 00 00 00 ff ff ff ff 05 00 00 00 25 61 66 66 25 00}  //weight: 1, accuracy: High
        $x_1_35 = {44 6f 70 49 44 31 00 00 ff ff ff ff 05 00 00 00 25 64 69 64 25 00}  //weight: 1, accuracy: High
        $x_1_36 = {41 66 66 49 44 00 00 00 4c 64 72 41 56 00}  //weight: 1, accuracy: High
        $x_1_37 = {6d 6b 72 6c 64 72 00}  //weight: 1, accuracy: High
        $x_1_38 = {2f 3f 61 3d 6c 26 69 64 3d 25 61 66 66 69 64 25 26 75 69 64 3d 25 75 69 64 25 00}  //weight: 1, accuracy: High
        $x_1_39 = {46 4e 55 4c 4c 00 00 00 ff ff ff ff 0a 00 00 00 2d 75 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_40 = {4e 55 4c 4c 4d 54 58 00}  //weight: 1, accuracy: High
        $x_2_41 = {5b 44 4f 4d 41 49 4e 32 5d 2f 77 69 6e 62 69 74 2e 62 6d 70 00}  //weight: 2, accuracy: High
        $x_1_42 = {5b 44 4f 4d 41 49 4e 31 5d 2f 3f 62 3d 25 61 66 66 69 64 25 00}  //weight: 1, accuracy: High
        $x_1_43 = {53 6f 66 74 77 61 72 65 5c 00 00 00 ff ff ff ff 05 00 00 00 41 56 33 36 30}  //weight: 1, accuracy: High
        $x_1_44 = {41 63 74 69 76 61 74 65 64 00 00 00 ff ff ff ff 05 00 00 00 41 66 66 49 44}  //weight: 1, accuracy: High
        $x_2_45 = {53 6f 66 74 77 61 72 65 5c 00 00 00 ff ff ff ff 03 00 00 00 45 56 41 00}  //weight: 2, accuracy: High
        $x_1_46 = {25 66 6e 61 6d 65 25 00}  //weight: 1, accuracy: High
        $x_1_47 = {54 45 56 41 4d 61 69 6e 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_48 = {72 65 67 44 65 76 56 65 72 4c 64 00}  //weight: 1, accuracy: High
        $x_2_49 = {41 66 66 49 44 00 00 00 ff ff ff ff 06 00 00 00 49 6e 74 4d 73 67 00}  //weight: 2, accuracy: High
        $x_1_50 = {40 67 5b 6f 4f 4e 5b 3f 75 21 00}  //weight: 1, accuracy: High
        $x_1_51 = {3c 77 5a 6f 55 68 57 3e 51 6a 63 3e 49 00}  //weight: 1, accuracy: High
        $x_2_52 = {b8 1a 00 00 00 e8 ?? ?? ?? ?? 8b d0 83 c2 61 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4b 75 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 40 08 2e}  //weight: 2, accuracy: Low
        $x_2_53 = {b8 04 00 00 00 e8 ?? ?? ?? ?? 8b 4d f8 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f4 8b 4d fc 8b d3 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 8b f8 57 56 e8 ?? ?? ?? ?? 6a 04 6a 00 8d 45 f0 8b 4d fc}  //weight: 2, accuracy: Low
        $x_2_54 = {b8 04 00 00 00 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 fc ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b f8 57 56 e8 ?? ?? ?? ?? 6a 04 6a 00 57 e8}  //weight: 2, accuracy: Low
        $x_2_55 = {05 10 0e 00 00 2b (c3|c6|c7) b9 10 0e 00 00 99 f7 f9 83 fa 0a 7e}  //weight: 2, accuracy: Low
        $x_1_56 = "Your system might be at a risk now." ascii //weight: 1
        $x_1_57 = "GetLicenseClick" ascii //weight: 1
        $x_1_58 = "ProtectClick" ascii //weight: 1
        $x_2_59 = "Attention! Zlob.PornAdvertiser.ba is in Standby mode now" ascii //weight: 2
        $x_2_60 = {03 c3 2b c6 99 f7 fb (83|42 83) 7e ?? (a1|8b 45)}  //weight: 2, accuracy: Low
        $x_2_61 = {55 6e 69 49 44 00 00 00 ff ff ff ff 08 00 00 00 46 65 65 64 62 61 63 6b 00}  //weight: 2, accuracy: High
        $x_1_62 = {5a 73 47 75 69 64 00}  //weight: 1, accuracy: High
        $x_1_63 = {6d 61 6c 7a 69 6c 6c 61 00 00 00 00 ff ff ff ff 04 00 00 00 76 62 6f 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

