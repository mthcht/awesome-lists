rule TrojanSpy_Win32_Batlopma_A_2147706395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Batlopma.A"
        threat_id = "2147706395"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Batlopma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FD16132738330604071F51CA57E94F3DCD69E47E9BABBBE3190E18232838C53CBB888DEA6BCC59F06DF" ascii //weight: 2
        $x_2_2 = "848E95A6858593BE5AE72114202A2127230B00173D3FC937B55BEB43C053DF05153A2B4DD65B3F" ascii //weight: 2
        $x_2_3 = "F41920373BC0B554CD59978E8795EC60FC19858CFC111359ADAD86889CBA4CBB3022256F" ascii //weight: 2
        $x_2_4 = "CE5A321E7D8581809BF07495A2A6B657383420183BC14C99DB4CD1D64827" ascii //weight: 2
        $x_2_5 = "432F0775D66BEF11341F40DC78829AB49B97BF878A92A3D0CE" ascii //weight: 2
        $x_2_6 = "80E9422E0D1531D074DF061E223E071911799B879CAB45B6CC47C14C4459EB2C" ascii //weight: 2
        $x_2_7 = "5A9F4DFE2EDD1F0563DA0A23C7" ascii //weight: 2
        $x_2_8 = "A2AE5CFC223CFB3CCB7AD8192EDC13D00CCD" ascii //weight: 2
        $x_2_9 = "8481BB649B4FCA6A8DBB14D20E1420DF003AEA" ascii //weight: 2
        $x_2_10 = "9386BC709647E011D1BA35F821C26B8FBB66" ascii //weight: 2
        $x_2_11 = "F7659C4DF72ADAADA4468DA95F8B" ascii //weight: 2
        $x_2_12 = "60F72FE81133CA7BCF5DF333D078BE65" ascii //weight: 2
        $x_1_13 = "CD44CD5BE979EF" ascii //weight: 1
        $x_1_14 = "4B23CD6EA1" ascii //weight: 1
        $x_1_15 = "002EC77AA65C90AB4C2763994F" ascii //weight: 1
        $x_1_16 = "78E71232E60277CEA75047" ascii //weight: 1
        $x_2_17 = "BC5C8AEB12C47BB97AD1C6BE7AD3AAA35C9851290A" ascii //weight: 2
        $x_2_18 = "64E26CFE091A36D576DD382B037D9FBE91B241E1022FDB76EB4BFB3BF0" ascii //weight: 2
        $x_2_19 = "6BE56F838D968A8199F2170860C053F25CF739F333E102085D84A2" ascii //weight: 2
        $x_2_20 = "94B2BB4EDA68E466E64C4EC1A997B9553AE80B25DA002A9AF80FCC7D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

