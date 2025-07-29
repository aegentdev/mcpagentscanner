import crewai
from crewai import Agent

print("eating")
HairyAgent = Agent(
    role= "Eater",
    goal="to eat",
    backstory="A brother who loves to eat",
    llm="twizzler"
)

