rule HackTool_Win32_ProductKey_2147658877_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProductKey"
        threat_id = "2147658877"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProductKey"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "utils/product_cd_key_viewer.html" ascii //weight: 1
        $x_1_2 = "Software\\NirSoft\\ProduKey" ascii //weight: 1
        $x_1_3 = "SoftwareKeyFile" ascii //weight: 1
        $x_1_4 = "ExtractWMIPartialKey" ascii //weight: 1
        $x_1_5 = "DigitalProductID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_ProductKey_G_2147762512_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProductKey.G!MSR"
        threat_id = "2147762512"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProductKey"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "z:\\Projects\\VS2005\\ProduKey\\Release\\ProduKey.pdb" ascii //weight: 1
        $x_1_2 = "Software\\NirSoft\\ProduKey" ascii //weight: 1
        $x_1_3 = "$$PRODUCKEY_TEMP_HIVE$$" ascii //weight: 1
        $x_1_4 = "Product key was not found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

