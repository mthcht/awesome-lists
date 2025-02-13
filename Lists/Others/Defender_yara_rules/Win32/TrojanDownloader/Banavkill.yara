rule TrojanDownloader_Win32_Banavkill_A_2147723761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banavkill.A"
        threat_id = "2147723761"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banavkill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AD5BF0220722DE10D76A93C3A55CF55D6BB8618EB5699F49EA0F24A084BB53FC66D60421D60B24DF0E3597F326CE6191A1DE86C2B6" ascii //weight: 2
        $x_2_2 = "25295EF50F0C7984809A9BDE7581998C85EB0A03122C32183234225DE272FD7581809996B33A28263BCF21AC35DCA9AFA790A7DB65F" ascii //weight: 2
        $x_1_3 = "11190972D77E98ACA89FB1CD67F90F6EDA2C31192E3AC34329" ascii //weight: 1
        $x_1_4 = "D0584831143ADC7193E4718A99A5DA1C689FAE869BADB945CF52F78C89F8" ascii //weight: 1
        $x_1_5 = "CB40BF52D672C757CF43C83A3DD5C132D11592A98B9395A9B5463141C15EFC0773E40177" ascii //weight: 1
        $x_1_6 = "D9708FA5809E8AA2A2A38B9CB6BE39B8A9FA031A323EC646CC62F0222B23224C54F80319047AC8" ascii //weight: 1
        $x_2_7 = "2A2455EC7D908C9AB582F50B6DD9175125A141EC1DC178AD4C83BF173AD07AD33ACF719A" ascii //weight: 2
        $x_2_8 = "0D3B4CDB62F56AF41265D02006708DEF449E59F22AC67AAC4EF20344E92FD0C715DD7A" ascii //weight: 2
        $x_2_9 = "B453A4B3BB5FFD080770DB1573E70567D30938E20A3DE11066885688" ascii //weight: 2
        $x_2_10 = "030D7E95A5A8A4B2AD9A8DE44337B4370355F722D30C3C20DD152D" ascii //weight: 2
        $x_2_11 = "D372839298BB50DE78CFBA36107AF770C41DC8093BEA17C371DC15BE60" ascii //weight: 2
        $x_1_12 = "093AA1BC59F80B3DC76690C375A9C6003292" ascii //weight: 1
        $x_1_13 = "3023589440F431E114" ascii //weight: 1
        $x_1_14 = "08167BEB60FC65DE74EC5ABA43CE3550C83237333525213FD057FA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

