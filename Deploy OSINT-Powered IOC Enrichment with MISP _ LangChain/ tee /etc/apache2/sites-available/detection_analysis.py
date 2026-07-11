
    data_count = analyzer.load_enriched_data()
    print(f"Loaded {data_count} enriched IOCs for analysis\n")
    
    # Perform various analyses
    analyzer.analyze_risk_distribution()
    analyzer.analyze_geographic_distribution()
    analyzer.identify_detection_gaps()
    analyzer.generate_detection_rules()
    analyzer.create_threat_intelligence_report()

if __name__ == "__main__":
    main()
