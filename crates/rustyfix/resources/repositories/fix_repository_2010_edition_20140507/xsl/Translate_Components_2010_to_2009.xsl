<?xml version="1.0" encoding="UTF-8"?>

<!--

Converts 2010 edition file to 2009 compatible file

Revisions
	01-Mar-2010		Phil Oliver
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="xml" version="1.0" encoding="UTF-8" indent="yes"/>

	<xsl:include href="Translate_support.xsl" />

	<xsl:template match="comment()" >
		<xsl:copy/>
	</xsl:template>

	<xsl:template match="processing-instruction()">
	  <xsl:copy/>
	</xsl:template>

	<xsl:template match="Component">
		<Components>
			<xsl:call-template name="translateEntityLevelAttributes2010to2009"><xsl:with-param name="cur" select="." /></xsl:call-template>

			<ComponentName><xsl:value-of select="Name" /></ComponentName>
			<xsl:copy-of select="ComponentType" />
			<Category><xsl:value-of select="CategoryID" /></Category>
			<MsgID><xsl:value-of select="ComponentID" /></MsgID>
			<xsl:copy-of select="Description" />
			<xsl:copy-of select="AbbrName" />
			<xsl:copy-of select="NotReqXML" />
		</Components>
	</xsl:template>

	<xsl:template match="Components">
		<dataroot copyright="Copyright (c) FIX Protocol Ltd. All Rights Reserved." edition="2009" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:noNamespaceSchemaLocation="../../schema/Components.xsd">
			<xsl:copy-of select="@version" />
			<xsl:copy-of select="@generated" />
			<xsl:if test="@latestEP"><xsl:attribute name="latestEP">EP<xsl:value-of select="@latestEP" /></xsl:attribute></xsl:if>
			<xsl:apply-templates />
		</dataroot>
	</xsl:template>

	<xsl:template match="/">
		<xsl:apply-templates />
	</xsl:template>
</xsl:stylesheet>
