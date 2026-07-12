#!/usr/bin/env python3
import json
import os
from dotenv import load_dotenv
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.schema import BaseOutputParser

load_dotenv()

class PCAPSummaryParser(BaseOutputParser):
    """Custom parser for PCAP analysis summaries"""
    
    def parse(self, text: str) -> dict:
        return {
            'summary': text,
            'recommendations': self.extract_recommendations(text),
            'risk_level': self.extract_risk_level(text)
        }
    
    def extract_recommendations(self, text):
        """Extract actionable recommendations from the summary"""
        lines = text.split('\n')
        recommendations = []
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['recommend', 'should', 'consider', 'implement']):
                recommendations.append(line.strip())
        
        return recommendations
    
    def extract_risk_level(self, text):
        """Determine overall risk level from the summary"""
        text_lower = text.lower()
        
        if any(keyword in text_lower for keyword in ['critical', 'severe', 'high risk', 'immediate']):
            return 'High'
        elif any(keyword in text_lower for keyword in ['moderate', 'medium', 'concerning']):
            return 'Medium'
        else:
            return 'Low'

class LangChainPCAPAssistant:
    def __init__(self):
        self.llm = OpenAI(
            temperature=0.3,
            openai_api_key=os.getenv('OPENAI_API_KEY')
        )
        self.parser = PCAPSummaryParser()
        self.setup_chains()
    
    def setup_chains(self):
        """Set up LangChain prompts and chains"""
        
        # Summary generation prompt
        summary_template = """
        You are a cybersecurity expert analyzing network traffic data. 
        Based on the following PCAP analysis report, provide a comprehensive summary of the findings:

        PCAP Analysis Report:
        {analysis_report}

        Please provide:
        1. Executive Summary of findings
        2. Key security concerns identified
        3. Risk assessment for each anomaly
        4. Actionable recommendations for remediation
        5. Priority levels for addressing issues

        Focus on practical, actionable insights that a network administrator can implement.
        """
        
        self.summary_prompt = PromptTemplate(
            input_variables=["analysis_report"],
            template=summary_template
        )
        
        self.summary_chain = LLMChain(
            llm=self.llm,
            prompt=self.summary_prompt,
            output_parser=self.parser
        )
        
        # Detailed analysis prompt
        detail_template = """
        As a network security analyst, provide detailed technical analysis for this specific anomaly:

        Anomaly Details:
        {anomaly_details}

        Network Context:
        {network_context}

        Provide:
        1. Technical explanation of the anomaly
        2. Potential attack vectors or causes
        3. Impact assessment
        4. Specific mitigation steps
        5. Monitoring recommendations

        Be specific and technical in your response.
        """
        
        self.detail_prompt = PromptTemplate(
            input_variables=["anomaly_details", "network_context"],
            template=detail_template
        )
        
        self.detail_chain = LLMChain(
            llm=self.llm,
            prompt=self.detail_prompt
        )
    
    def generate_summary(self, analysis_report):
        """Generate AI-powered summary of PCAP analysis"""
        try:
            result = self.summary_chain.run(
                analysis_report=json.dumps(analysis_report, indent=2)
            )
            return result
        except Exception as e:
            return {
                'summary': f"Error generating summary: {str(e)}",
                'recommendations': [],
                'risk_level': 'Unknown'
            }
    
    def analyze_specific_anomaly(self, anomaly, network_context):
        """Provide detailed analysis of specific anomaly"""
        try:
            result = self.detail_chain.run(
                anomaly_details=json.dumps(anomaly, indent=2),
                network_context=json.dumps(network_context, indent=2)
            )
            return result
        except Exception as e:
            return f"Error analyzing anomaly: {str(e)}"
    
    def generate_comprehensive_report(self, pcap_analysis):
        """Generate comprehensive AI-enhanced report"""
        
        # Generate overall summary
        overall_summary = self.generate_summary(pcap_analysis)
        
        # Analyze each anomaly in detail
        detailed_analyses = []
        for anomaly in pcap_analysis.get('anomalies_detected', []):
            detailed_analysis = self.analyze_specific_anomaly(
                anomaly, 
                pcap_analysis['basic_statistics']
            )
            detailed_analyses.append({
                'anomaly': anomaly,
                'ai_analysis': detailed_analysis
            })
        
        return {
            'overall_summary': overall_summary,
            'detailed_anomaly_analyses': detailed_analyses,
            'original_analysis': pcap_analysis
        }

if __name__ == "__main__":
    # Load the PCAP analysis report
    with open('pcap_analysis_report.json', 'r') as f:
        pcap_data = json.load(f)
    
    # Initialize the AI assistant
    assistant = LangChainPCAPAssistant()
    
    # Generate comprehensive AI-enhanced report
    ai_report = assistant.generate_comprehensive_report(pcap_data)
    
    # Save the enhanced report
    with open('ai_enhanced_pcap_report.json', 'w') as f:
        json.dump(ai_report, f, indent=2)
    
    print("AI-Enhanced PCAP Analysis Complete!")
    print("\nOverall Risk Level:", ai_report['overall_summary']['risk_level'])
    print("\nKey Recommendations:")
    for rec in ai_report['overall_summary']['recommendations'][:3]:
        print(f"- {rec}")
    
    print(f"\nDetailed analyses for {len(ai_report['detailed_anomaly_analyses'])} anomalies")
    print("Full report saved to: ai_enhanced_pcap_report.json")
