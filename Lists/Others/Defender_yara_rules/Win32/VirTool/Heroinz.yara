rule VirTool_Win32_Heroinz_A_2147832711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Heroinz.A!MTB"
        threat_id = "2147832711"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Heroinz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "heroinn_client::module::ftp" ascii //weight: 1
        $x_1_2 = "heroinn_client::configheroinn_client\\src" ascii //weight: 1
        $x_1_3 = "heroinn_util\\src\\packet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

