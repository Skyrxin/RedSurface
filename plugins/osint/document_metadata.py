"""
Document Metadata Plugin — Extracts metadata from public documents using search engines.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType

class DocumentMetadataPlugin(PluginBase):
    name = "Document Metadata Extractor"
    description = "Searches for public documents (PDF, DOCX) on the target domain and extracts metadata like authors and software versions."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["document_metadata"]
    target_types = ["domain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="document_metadata")
        
        from modules.osint import OSINTCollector
        collector = OSINTCollector()
        
        documents = await collector.extract_document_metadata(target)
        
        for doc in documents:
            if "author" in doc:
                 result.values.append(f"Document by {doc['author']}")
        
        if not documents:
            result.values = [f"No public documents with metadata found for {target}"]
            
        result.metadata = {"documents": documents}
        result.success = True
        
        return result
