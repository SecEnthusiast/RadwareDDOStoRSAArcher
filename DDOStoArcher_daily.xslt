<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output encoding="UTF-8"/>
	<xsl:template match="/">
		<Records>
			<xsl:variable name="device" select="Title/combined-Reports/Devices"/>
			<xsl:variable name="period" select="Title/combined-Reports/Period"/>
			<xsl:variable name="timezone" select="Title/combined-Reports/Time-Zone"/>
			<xsl:variable name="tables" select="Title/combined-Reports/Tables"/>
			<xsl:for-each select="Title/combined-Reports/Group/Group/Report/Row">
				<xsl:if test="../@name = 'Attacks Allowed and Denied'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[@name]"/>
						</policyname_filter>
						<Action>
							<xsl:value-of select="Column[1]/text()"/>
						</Action>
						<Attack_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Attack_Name>
						<Policy_Name>
							<xsl:value-of select="Column[3]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[4]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[5]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[6]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>

				<xsl:if test="../@name = 'Attacks by Threat Category'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Threat_Category>
							<xsl:value-of select="Column[1]/text()"/>
						</Threat_Category>
						<Attack_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Attack_Name>
						<Policy_Name>
							<xsl:value-of select="Column[3]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[4]/text()"/>
						</VLAN_Tag>
						<Risk>
							<xsl:value-of select="Column[5]/text()"/>
						</Risk>
						<Last_timestamp>
							<xsl:value-of select="Column[6]/text()"/>
						</Last_timestamp>
						<Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[8]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[11]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[12]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Attack Sources'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Source_IP>
							<xsl:value-of select="Column[1]/text()"/>
						</Source_IP>
						<Source_Port>
							<xsl:value-of select="Column[2]/text()"/>
						</Source_Port>
						<Policy_Name>
							<xsl:value-of select="Column[3]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[4]/text()"/>
						</VLAN_Tag>
						<Country>
							<xsl:value-of select="Column[5]/text()"/>
						</Country>
						<Count>
							<xsl:value-of select="Column[6]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[7]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[11]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Attacked Destinations'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Destination_IP>
							<xsl:value-of select="Column[1]/text()"/>
						</Destination_IP>
						<Policy_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[3]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[4]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[5]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[6]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Attacks'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Attack_Name>
							<xsl:value-of select="Column[1]/text()"/>
						</Attack_Name>
						<Policy_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[3]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[4]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[5]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[6]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Attacks by Bandwidth'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Attack_Name>
							<xsl:value-of select="Column[1]/text()"/>
						</Attack_Name>
						<Policy_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[3]/text()"/>
						</VLAN_Tag>
						<Packets>
							<xsl:value-of select="Column[4]/text()"/>
						</Packets>
						<Packets_percentage>
							<xsl:value-of select="Column[5]/text()"/>
						</Packets_percentage>
						<Mbits>
							<xsl:value-of select="Column[6]/text()"/>
						</Mbits>
						<Mbits_percentage>
							<xsl:value-of select="Column[7]/text()"/>
						</Mbits_percentage>
						<Today_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[11]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Attacks by Duration'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Duration>
							<xsl:value-of select="Column[1]/text()"/>
						</Duration>
						<Attack_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Attack_Name>
						<Policy_Name>
							<xsl:value-of select="Column[3]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[4]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[5]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[6]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Probed Applications'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Application_Name>
							<xsl:value-of select="Column[1]/text()"/>
						</Application_Name>
						<Protocol>
							<xsl:value-of select="Column[2]/text()"/>
						</Protocol>
						<Destination_Port>
							<xsl:value-of select="Column[3]/text()"/>
						</Destination_Port>
						<Policy_Name>
							<xsl:value-of select="Column[4]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[5]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[6]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[7]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[10]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[11]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Top Probed IP Addresses'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Destination_IP>
							<xsl:value-of select="Column[1]/text()"/>
						</Destination_IP>
						<Policy_Name>
							<xsl:value-of select="Column[2]/text()"/>
						</Policy_Name>
						<VLAN_Tag>
							<xsl:value-of select="Column[3]/text()"/>
						</VLAN_Tag>
						<Count>
							<xsl:value-of select="Column[4]/text()"/>
						</Count>
						<Count_percentage>
							<xsl:value-of select="Column[5]/text()"/>
						</Count_percentage>
						<Today_Count>
							<xsl:value-of select="Column[6]/text()"/>
						</Today_Count>
						<Yesterday_Count>
							<xsl:value-of select="Column[7]/text()"/>
						</Yesterday_Count>
						<Last_7_Days_Count>
							<xsl:value-of select="Column[8]/text()"/>
						</Last_7_Days_Count>
						<Current_Month_Count>
							<xsl:value-of select="Column[9]/text()"/>
						</Current_Month_Count>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Bandwidth by Hour of Day(Kbps)'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Hour>
							<xsl:value-of select="Column[1]/text()"/>
						</Hour>
						<Physical_Port>
							<xsl:value-of select="Column[2]/text()"/>
						</Physical_Port>
						<Kbps>
							<xsl:value-of select="Column[3]/text()"/>
						</Kbps>
					</Record>
				</xsl:if>
				<xsl:if test="../@name = 'Most Active Days(Kbps)'">
					<Record>
						<unique_ID>
							<xsl:value-of select="generate-id(.)" />
						</unique_ID>
						<Report_Group>
							<xsl:value-of select="../../../@name"/>
						</Report_Group>
						<Report_Type>
							<xsl:value-of select="../../@name"/>
						</Report_Type>
						<Report_Name>
							<xsl:value-of select="../@name"/>
						</Report_Name>
						<device>
							<xsl:value-of select="$device"/>
						</device>
						<period>
							<xsl:value-of select="$period"/>
						</period>
						<timezone>
							<xsl:value-of select="$timezone"/>
						</timezone>
						<policyname_filter>
							<xsl:value-of select="../Applied-Filters[1]/Column[1]/text()"/>
						</policyname_filter>
						<Day>
							<xsl:value-of select="Column[1]/text()"/>
						</Day>
						<Physical_Port>
							<xsl:value-of select="Column[2]/text()"/>
						</Physical_Port>
						<Kbps>
							<xsl:value-of select="Column[3]/text()"/>
						</Kbps>
					</Record>
				</xsl:if>
			</xsl:for-each>
		</Records>
	</xsl:template>
</xsl:stylesheet>