rule Trojan_Win32_PurpleWave_A_2147761178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PurpleWave.A!MTB"
        threat_id = "2147761178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PurpleWave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sumakokl.beget.tech/config" ascii //weight: 1
        $x_1_2 = "PurpleWave" ascii //weight: 1
        $x_1_3 = ":[epmapper,Security=Impersonation Dynamic False]" ascii //weight: 1
        $x_1_4 = "\\History.IE5\\MSHist" ascii //weight: 1
        $x_1_5 = "\\BaseNamedObjects\\Global\\SvcctrlStartEvent_A3752DX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_PurpleWave_B_2147761179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PurpleWave.B!MTB"
        threat_id = "2147761179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PurpleWave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ca 02 c9 8a c1 0c 01 84 d2 0f b6 c0 89 ?? ?? 8b d0 0f b6 c1 0f 49 d0 89 ?? ?? 83 eb 01 75 [0-4] [0-21] 88 04 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

