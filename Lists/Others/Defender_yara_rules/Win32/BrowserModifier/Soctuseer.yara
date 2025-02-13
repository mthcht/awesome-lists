rule BrowserModifier_Win32_Soctuseer_233287_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WWE_uninstall.exe" ascii //weight: 1
        $x_1_2 = "Socia2Searc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://install-apps.com/s2s_install.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "WBE_uninstall.exe" ascii //weight: 50
        $x_1_2 = "Social2Se Browser Enhancer" ascii //weight: 1
        $x_1_3 = "Socia2Sear Browser Enhancer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00}  //weight: 50, accuracy: High
        $x_50_2 = "wajam_goblin.pdb" ascii //weight: 50
        $x_1_3 = "Social2S" wide //weight: 1
        $x_1_4 = "Socia2Search" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00}  //weight: 50, accuracy: High
        $x_50_2 = "wajam_goblin_64.pdb" ascii //weight: 50
        $x_1_3 = "Social2S" wide //weight: 1
        $x_1_4 = "Socia2Search" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WWE_uninstall.exe" wide //weight: 1
        $x_1_2 = "/DELETE_ON_CLOSE" wide //weight: 1
        $x_1_3 = "/NAME Social2Sear" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-6] 5c 73 72 63 5c 68 74 74 70 5f 69 6e 74 65 72 63 65 70 74 69 6f 6e 5c [0-64] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "Socia2Searc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 64 6c 6c 00 62 75 6c 62 75 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" wide //weight: 1
        $x_1_4 = "Socia2Searc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = "<script data-type=\"injected\" src=\"%1%%2%%3%%4%\"></script>" ascii //weight: 1
        $x_1_3 = "v=d%1%&os_mj=%2%&os_mn=%3%&os_bitness=%4%" ascii //weight: 1
        $x_1_4 = "Socia2Searc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Socia2Sear" wide //weight: 20
        $x_1_2 = "wtf! cannot create the thread" ascii //weight: 1
        $x_1_3 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" wide //weight: 1
        $x_1_4 = "AVQuicEncryptedPacket@net@@" ascii //weight: 1
        $x_1_5 = "AVquic_request_parser@http_parsing@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AUunregistry_driver@@" ascii //weight: 1
        $x_1_2 = "AUprepare_defense_driver_update@@" ascii //weight: 1
        $x_1_3 = "AUunzip_patcher_service@@" ascii //weight: 1
        $x_1_4 = "AU?$error_info_injector@Vbad_format_string@io@boost@@@exception_detail@boost@@" ascii //weight: 1
        $x_1_5 = "AV?$_Ref_count_obj@Uinjection@html_injection@@@std@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Soctuseer_233287_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Social2S" wide //weight: 10
        $x_1_2 = "Browser Enhancer" wide //weight: 1
        $x_1_3 = "nss\\certutil -A -t \"TCu\" -i \"" wide //weight: 1
        $x_1_4 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" wide //weight: 1
        $x_1_5 = "--apply_searchpage_search_provider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Social2Sear Monitor" wide //weight: 20
        $x_1_2 = "3045035B-3C14-4698-8AC4-ADB18CC42C1E" wide //weight: 1
        $x_1_3 = "folder of wajam dll" ascii //weight: 1
        $x_1_4 = "path to patch.zip" ascii //weight: 1
        $x_1_5 = "apply a downloaded patch" ascii //weight: 1
        $x_1_6 = "inject dll into target process" ascii //weight: 1
        $x_1_7 = "manual_mapping_inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Social2S" wide //weight: 10
        $x_1_2 = "--patch_cfg_file=" wide //weight: 1
        $x_1_3 = "--apply_patch --patch=" wide //weight: 1
        $x_1_4 = "WBE_uninstall.exe" wide //weight: 1
        $x_1_5 = "Global\\C803531D-06D8-43CD-BD53-38F632596B9A" wide //weight: 1
        $x_1_6 = "<script data-type=\"injected\" src=\"%1%%2%%3%%4%\"></script>" ascii //weight: 1
        $x_1_7 = "wtf! unsupported patch type: %1%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_14
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "--apply_patch" ascii //weight: 10
        $x_10_2 = "wajam.dll" wide //weight: 10
        $x_1_3 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-24] 5c 73 72 63 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 6d 6f 74 69 2d [0-16] 5c 73 72 63 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-6] 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c 10 00 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = "7f5ed85d-6828-4f92-858c-f40b0ac68138" wide //weight: 1
        $x_1_7 = ".?AVAsmHelperBase@blackbone@@" ascii //weight: 1
        $x_1_8 = ".?AV?$_Ref_count_del@PAUHINSTANCE__@@V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Soctuseer_233287_15
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Soctuseer"
        threat_id = "233287"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Soctuseer"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "--apply_patch" ascii //weight: 10
        $x_10_2 = "wajam_64.dll" wide //weight: 10
        $x_1_3 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-24] 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 5f 36 34 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 6d 6f 74 69 2d [0-16] 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 5f 36 34 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-6] 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c [0-64] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d [0-6] 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c 10 00 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_7 = ".?AVAsmHelperBase@blackbone@@" ascii //weight: 1
        $x_1_8 = ".?AVAsmHelper64@blackbone@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

