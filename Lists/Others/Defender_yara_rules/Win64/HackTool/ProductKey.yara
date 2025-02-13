rule HackTool_Win64_ProductKey_G_2147765679_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ProductKey.G!MSR"
        threat_id = "2147765679"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ProductKey"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Projects\\VS2005\\ProduKey\\x64\\Release\\ProduKey.pdb" ascii //weight: 1
        $x_1_2 = "Software\\NirSoft\\ProduKey" ascii //weight: 1
        $x_1_3 = "utils/product_cd_key_viewer.html" ascii //weight: 1
        $x_1_4 = "$$PRODUCKEY_TEMP_HIVE$$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

