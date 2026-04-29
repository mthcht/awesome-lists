rule HackTool_Win32_cloudflared_A_2147968016_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/cloudflared.A"
        threat_id = "2147968016"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "cloudflared"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "github.com/cloudflare/cloudflared" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

