# -*- coding: utf-8 -*-
import scrapy


class IfconfigSpider(scrapy.Spider):
    name = 'ifconfig'
    allowed_domains = ['ifconfig.io']
    start_urls = ['http://ifconfig.io/']

    def parse(self, response):
        pass
