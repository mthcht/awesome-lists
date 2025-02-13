rule Worm_Win32_Virenkqut_A_2147684631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Virenkqut.A"
        threat_id = "2147684631"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Virenkqut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nUrOtUa[" wide //weight: 1
        $x_1_2 = "eXe.%Sftn%\\\\noiTAmrOfnI.EmUlOv.mEtSys\\\\\\\\..=dnAMMoc\\\\NEPo\\\\\\\\LlEhs" wide //weight: 1
        $x_1_3 = "EXe.%sFTn%//NoItAMRoFNi.eMuLov.MeTsYs=DNammOc\\suriV itnA htiW hcraeS\\lleHs" wide //weight: 1
        $x_1_4 = "Shell32.js" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

