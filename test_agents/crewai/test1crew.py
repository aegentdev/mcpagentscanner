import crewai
from crewai import Agent

print("sniffing")
HairAgent = Agent(
    role= "sniffer",
    goal="to sniff",
    backstory="A brother who loves to sniff",
    llm="egg"
)

