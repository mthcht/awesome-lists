rule BrowserModifier_Win32_Vonteera_205893_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 a0 fd ff ff 50 68 04 01 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 a0 fd ff ff 68 22 01 00 00 50 e8 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{6DD1B906-45FA-4A57-9AC6-01108C25067F}" wide //weight: 1
        $x_1_2 = "AVCNoVooITPluginModule@@" ascii //weight: 1
        $x_1_3 = "$_IDispEventLocator@$00$1?DIID_DWebBrowserEvents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TypeLib' = s '{3FC2D59A-5C76-1E97-30DC-1EC6784419E5}'" ascii //weight: 1
        $x_1_2 = "ProgID = s 'DigiAd.DigiAd.1'" ascii //weight: 1
        $x_1_3 = "ForceRemove {2ED35963-FCC9-4698-B619-787FE1C75079} = s 'DigiAd Class'" ascii //weight: 1
        $x_1_4 = "script.id = \"adnetworkme_js\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "addon@Vonteera.com" ascii //weight: 1
        $x_1_2 = "Software\\Vonteera Safe ads" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\NoVooITSet" ascii //weight: 1
        $x_1_4 = "\\NoVooITAddon" ascii //weight: 1
        $x_1_5 = "www.acdcads.com/aff/thanks/thanks3.php?code=" ascii //weight: 1
        $x_1_6 = "/output:\"sn.txt\" bios get serialnumber" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apsrunner/ADSKO/noodleup.exe" wide //weight: 1
        $x_1_2 = "apsrunner/ADSKO/ver.txt" wide //weight: 1
        $x_1_3 = "Software\\noodsrunner" wide //weight: 1
        $x_1_4 = "noodrun.exe" wide //weight: 1
        $x_1_5 = "/SC DAILY /TN \"nod01\"" wide //weight: 1
        $x_1_6 = "hjmjt.kkp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TypeLib' = s '{3FC2D59A-5C76-1E97-30DC-1EC6784419E5}'" ascii //weight: 2
        $x_2_2 = "ProgID = s 'adTech.adTech.1'" ascii //weight: 2
        $x_2_3 = "ForceRemove {934B156A-3D17-3981-B78A-5C138F423AD6} = s 'adTech Class'" ascii //weight: 2
        $x_1_4 = "www.adnetworkus.com" wide //weight: 1
        $x_1_5 = "www.adfactorytech.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Vonteera_205893_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var _0xec03=[\"\",\"\\x68\\x74\\x74\\x70\\x3A\\x2F\\x2F\\x77\\x77\\x77\\x2E\\x61\\x6C\\x61\\x72\\x61\\x62\\x65\\x79\\x65\\x73\\x2E\\x63\\x6F\\x6D" ascii //weight: 1
        $x_1_2 = "gRandScriptUrls[_0xec03[56]+_0xe525x2b[0]][_0xec03[61]]" ascii //weight: 1
        $x_1_3 = "var _0xe525x27= new XMLHttpRequest();_0xe525x27[_0xec03[50]](_0xec03[49]," ascii //weight: 1
        $x_1_4 = "var _0xe525x23=localStorage[_0xec03[45]];if(!_0xe525x23||parseInt(_0xe525x23)===NaN)" ascii //weight: 1
        $x_1_5 = "/Delete /tn \"mium0d\" /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Vonteera_205893_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Vonteera"
        threat_id = "205893"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Vonteera"
        severity = "42"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 75 6e 63 74 69 6f 6e 20 69 6e 69 74 54 61 62 4e 65 77 48 6f 6f 6b 28 29 7b 0d 0a 0a 00 63 68 72 6f 6d 65 2e 74 61 62 73 2e 6f 6e 43 72 65 61 74 65 64 2e 61 64 64 4c 69 73 74 65 6e 65 72 28 66 75 6e 63 74 69 6f 6e 28 74 61 62 29 7b}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 72 6f 6d 65 2e 74 61 62 73 2e 67 65 74 28 74 61 62 5f 69 64 2c 05 00 63 68 65 63 6b 5f 66 6f 72 5f 6a 73 5f 69 6e 6a 65 63 74 69 6f 6e 29 3b}  //weight: 1, accuracy: Low
        $x_1_3 = {66 75 6e 63 74 69 6f 6e 20 61 64 64 5f 72 65 6d 6f 76 65 5f 73 63 72 69 70 74 28 75 72 6c 29 05 00 7b 05 00 72 65 74 75 72 6e 20 27 76 61 72 20 41 64 74 65 63 68 5f 75 73 65 72 73 5f 6a 73}  //weight: 1, accuracy: Low
        $x_1_4 = "gRandScriptUrls[\"ht\" + tmp[0]].push(\"ht\" + tmp[0] + \"://\" + tmp[1] + \".\" + tmp[2] + \"/\" + ((tmp[3] === \":\") ? \"\" : (tmp[3].replace(/\\:/, \"\") + \"/\")) + tmp[4] + \".js\");" ascii //weight: 1
        $x_1_5 = "console.log('Injected to', tab.url);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

